package filter

import (
	"crypto/md5"
	"fmt"
	"net/url"
	"strings"
	"time"

	"odysseyshield/internal/config"
	"odysseyshield/internal/storage"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Action describes the moderation reaction to a message.
type Action int

const (
	ActionNone Action = iota
	ActionWarn        // delete + auto-deleted soft warning
	ActionMute        // delete + mute for configured duration
	ActionBan         // delete + permanent ban
)

func (a Action) String() string {
	switch a {
	case ActionWarn:
		return "warn"
	case ActionMute:
		return "mute"
	case ActionBan:
		return "ban"
	default:
		return "none"
	}
}

// Result holds the outcome of analysing a single message.
type Result struct {
	Score   int
	Reasons []string
	Action  Action
}

// Filter performs spam detection.
type Filter struct {
	cfg   *config.Config
	store *storage.Storage
}

// New constructs a Filter.
func New(cfg *config.Config, store *storage.Storage) *Filter {
	return &Filter{cfg: cfg, store: store}
}

// Analyze scores a message and returns the recommended action.
// Call only after verifying msg.From is non-nil.
func (f *Filter) Analyze(msg *tgbotapi.Message) Result {
	text, entities, buttonURLs := messageContentForAnalysis(msg)
	scanText := normalizeFilterText(text)

	var score int
	var reasons []string

	// Strikethrough / combining-mark obfuscation (О̷ф̷и̷ц̷и̷а̷л̷ь̷н̷о̷-style).
	if ratio := combiningMarkRatio(text); ratio >= 0.2 {
		score += 30
		reasons = append(reasons, "unicode_format_evasion")
	}

	// Check for spam replies (short "+" / thanks on spam bait).
	if msg.ReplyToMessage != nil {
		trimmed := strings.TrimSpace(text)
		rLen := len([]rune(trimmed))
		if trimmed == "+" || strings.EqualFold(trimmed, "спасибо") || rLen <= 2 {
			score += 50
			reasons = append(reasons, "spam_reply")
		}
	}

	userID := msg.From.ID
	chatID := msg.Chat.ID

	userState := f.store.GetOrCreateUser(userID)
	isNewUser := userState.MessageCount < f.cfg.NewUserMessages

	// ── 1. Keyword scoring (on normalized text) ─────────────────
	score, reasons = applyPatterns(scanText, score, reasons, VPNPatterns)
	score, reasons = applyPatterns(scanText, score, reasons, PhishingPatterns)
	score, reasons = applyPatterns(scanText, score, reasons, ScamJobPatterns)
	score, reasons = applyPatterns(scanText, score, reasons, BanPatterns)
	score, reasons = applyPatterns(scanText, score, reasons, CTAPatterns)

	// ── 2. Link analysis ────────────────────────────────────────
	urls := extractURLsFromEntities(text, entities)
	urls = append(urls, buttonURLs...)

	// Spam via inline URL buttons (often no copyable text in message body).
	if n := len(buttonURLs); n > 0 {
		score += 35
		reasons = append(reasons, "inline_url_button")
		if strings.TrimSpace(messageBodyText(msg)) == "" {
			score += 25
			reasons = append(reasons, "url_buttons_only")
		}
	}

	// Foreign invite links (body + inline button URLs)
	for _, src := range append([]string{scanText}, buttonURLs...) {
		for _, inv := range InviteLinkRe.FindAllString(src, -1) {
			if !f.isAllowedInvite(inv) {
				score += 40
				reasons = append(reasons, "foreign_invite")
			}
		}
	}

	for _, rawURL := range urls {
		domain := extractDomain(rawURL)
		if domain == "" {
			continue
		}
		switch {
		case f.isWhitelistedDomain(domain):
			score -= 10
		case f.isBlacklistedDomain(domain):
			score += 30
			reasons = append(reasons, "blacklist:"+domain)
		case ShortURLHostRe.MatchString(domain):
			score += 25
			reasons = append(reasons, "short_url:"+domain)
		}
	}

	// ── 3. Behavioural signals ──────────────────────────────────

	// New user + any URL in first message
	if isNewUser && len(urls) > 0 {
		score += 20
		reasons = append(reasons, "new_user_with_link")
	}

	// Excessive mentions
	mentionCount := countMentions(entities)
	if mentionCount > 3 {
		score += 15
		reasons = append(reasons, fmt.Sprintf("many_mentions:%d", mentionCount))
	}

	// Excessive emoji
	if emojiCount := countEmoji(text); emojiCount > 8 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("many_emoji:%d", emojiCount))
	}

	// Media + link (typical ad pattern)
	hasMedia := msg.Photo != nil || msg.Document != nil || msg.Video != nil
	if hasMedia && len(urls) > 0 {
		score += 15
		reasons = append(reasons, "media_with_link")
	}

	// Forward from untrusted external channel
	if msg.ForwardFromChat != nil && !f.cfg.IsTrustedChat(msg.ForwardFromChat.ID) {
		score += 25
		reasons = append(reasons, "foreign_forward")
	}

	// Duplicate / repeated message from the same user in this chat (skip very short texts).
	hash := messageHash(scanText)
	if scanText != "" && len([]rune(scanText)) >= 35 && f.store.IsDuplicate(chatID, userID, hash) {
		score += 35
		reasons = append(reasons, "duplicate_message")
	}
	f.store.RecordMessage(chatID, userID, hash)

	// ── 4. Exemptions & multipliers ─────────────────────────────
	score, reasons = applyExemptions(scanText, score, reasons)
	if score > 0 && isNewUser {
		score = int(float64(score) * 1.5)
		reasons = append(reasons, "×1.5_new_user")
	}

	nm := f.cfg.NightMode
	if score > 0 && nm.Enabled && isNightMode(nm.StartHour, nm.EndHour) {
		score = int(float64(score) * nm.RiskMultiplier)
		reasons = append(reasons, fmt.Sprintf("×%.1f_night_mode", nm.RiskMultiplier))
	}

	// Clamp to zero
	if score < 0 {
		score = 0
	}

	// ── 5. Determine action ─────────────────────────────────────
	var action Action
	switch {
	case score >= f.cfg.RiskThresholds.Ban:
		action = ActionBan
	case score >= f.cfg.RiskThresholds.Mute:
		action = ActionMute
	case score >= f.cfg.RiskThresholds.Warn:
		action = ActionWarn
	default:
		action = ActionNone
	}

	action = softenAction(action, score, reasons, configThresholds{
		Warn: f.cfg.RiskThresholds.Warn,
		Mute: f.cfg.RiskThresholds.Mute,
		Ban:  f.cfg.RiskThresholds.Ban,
	})

	return Result{Score: score, Reasons: reasons, Action: action}
}

// ── helpers ──────────────────────────────────────────────────────

func applyPatterns(text string, score int, reasons []string, patterns []WeightedPattern) (int, []string) {
	for _, wp := range patterns {
		if wp.Re.MatchString(text) {
			score += wp.Weight
			reasons = append(reasons, wp.Label)
		}
	}
	return score, reasons
}

func messageBodyText(msg *tgbotapi.Message) string {
	if msg.Text != "" {
		return msg.Text
	}
	return msg.Caption
}

func messageTextAndEntities(msg *tgbotapi.Message) (string, []tgbotapi.MessageEntity) {
	if msg.Text != "" {
		return msg.Text, msg.Entities
	}
	return msg.Caption, msg.CaptionEntities
}

// messageContentForAnalysis merges body text/caption with inline-keyboard labels
// and collects URL targets from inline buttons (invisible in plain message text).
func messageContentForAnalysis(msg *tgbotapi.Message) (string, []tgbotapi.MessageEntity, []string) {
	text, entities := messageTextAndEntities(msg)
	var buttonURLs, buttonLabels []string

	if msg.ReplyMarkup != nil {
		for _, row := range msg.ReplyMarkup.InlineKeyboard {
			for _, btn := range row {
				if btn.Text != "" {
					buttonLabels = append(buttonLabels, btn.Text)
				}
				if btn.URL != nil && *btn.URL != "" {
					buttonURLs = append(buttonURLs, *btn.URL)
				}
				if btn.LoginURL != nil && btn.LoginURL.URL != "" {
					buttonURLs = append(buttonURLs, btn.LoginURL.URL)
				}
			}
		}
	}

	if len(buttonLabels) > 0 {
		labels := strings.Join(buttonLabels, "\n")
		if text != "" {
			text += "\n" + labels
		} else {
			text = labels
		}
	}
	if len(buttonURLs) > 0 {
		if text != "" {
			text += "\n" + strings.Join(buttonURLs, "\n")
		} else {
			text = strings.Join(buttonURLs, "\n")
		}
	}

	return text, entities, buttonURLs
}

func extractURLsFromEntities(text string, entities []tgbotapi.MessageEntity) []string {
	var urls []string
	runes := []rune(text)
	for _, e := range entities {
		switch e.Type {
		case "url":
			end := e.Offset + e.Length
			if end <= len(runes) {
				urls = append(urls, string(runes[e.Offset:end]))
			}
		case "text_link":
			if e.URL != "" {
				urls = append(urls, e.URL)
			}
		}
	}
	return urls
}

func countMentions(entities []tgbotapi.MessageEntity) int {
	n := 0
	for _, e := range entities {
		if e.Type == "mention" || e.Type == "text_mention" {
			n++
		}
	}
	return n
}

func countEmoji(text string) int {
	n := 0
	for _, r := range text {
		if isEmojiRune(r) {
			n++
		}
	}
	return n
}

func isEmojiRune(r rune) bool {
	return (r >= 0x1F600 && r <= 0x1F64F) ||
		(r >= 0x1F300 && r <= 0x1F5FF) ||
		(r >= 0x1F680 && r <= 0x1F6FF) ||
		(r >= 0x1F700 && r <= 0x1F77F) ||
		(r >= 0x1F780 && r <= 0x1F7FF) ||
		(r >= 0x1F800 && r <= 0x1F8FF) ||
		(r >= 0x1F900 && r <= 0x1F9FF) ||
		(r >= 0x1FA00 && r <= 0x1FA6F) ||
		(r >= 0x1FA70 && r <= 0x1FAFF) ||
		(r >= 0x2702 && r <= 0x27B0)
}

func extractDomain(rawURL string) string {
	if !strings.HasPrefix(strings.ToLower(rawURL), "http") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	return host
}

func messageHash(text string) string {
	normalized := strings.ToLower(strings.TrimSpace(normalizeFilterText(text)))
	return fmt.Sprintf("%x", md5.Sum([]byte(normalized)))
}

func isNightMode(start, end int) bool {
	h := time.Now().Hour()
	if start > end { // crosses midnight (e.g. 23 → 7)
		return h >= start || h < end
	}
	return h >= start && h < end
}

func (f *Filter) isAllowedInvite(link string) bool {
	for _, allowed := range f.cfg.AllowedInvites {
		if strings.Contains(link, allowed) {
			return true
		}
	}
	return false
}

func (f *Filter) isWhitelistedDomain(domain string) bool {
	for _, d := range f.cfg.WhitelistDomains {
		d = strings.ToLower(d)
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func (f *Filter) isBlacklistedDomain(domain string) bool {
	for _, d := range f.cfg.BlacklistDomains {
		d = strings.ToLower(d)
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
