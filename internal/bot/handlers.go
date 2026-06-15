package bot

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"odysseyshield/internal/filter"
	"odysseyshield/internal/storage"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// ── Router ────────────────────────────────────────────────────────

func (b *Bot) handleUpdate(upd tgbotapi.Update) {
	switch {
	case upd.Message != nil:
		msg := upd.Message
		log.Printf("Update %d: chat=%d type=%s from=%v text_len=%d",
			upd.UpdateID, msg.Chat.ID, msg.Chat.Type, msg.From != nil, len(messageText(msg)))
		b.handleMessage(msg)
	case upd.CallbackQuery != nil:
		log.Printf("Update %d: callback from=%d", upd.UpdateID, upd.CallbackQuery.From.ID)
		b.handleCallback(upd.CallbackQuery)
	default:
		log.Printf("Update %d: unhandled type", upd.UpdateID)
	}
}

// ── Message handler ───────────────────────────────────────────────

func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	// Skip channel posts and anonymous-admin messages (SenderChat set, From nil or bot).
	if msg.From == nil {
		log.Printf("Skip msg %d: no From (channel/anonymous post?)", msg.MessageID)
		return
	}
	if msg.SenderChat != nil {
		log.Printf("Skip msg %d: SenderChat set", msg.MessageID)
		return
	}

	userID := msg.From.ID
	chatID := msg.Chat.ID

	// Trusted users bypass all filters (by ID or username).
	if b.cfg.IsTrustedUser(userID) || b.cfg.IsTrustedUsername(msg.From.UserName) {
		log.Printf("Skip msg %d: trusted user %d", msg.MessageID, userID)
		b.store.IncrementMessageCount(userID)
		return
	}

	// Chat admins bypass all filters (cached check).
	if b.isAdmin(chatID, userID) {
		log.Printf("Skip msg %d: chat admin %d", msg.MessageID, userID)
		b.store.IncrementMessageCount(userID)
		return
	}

	result := b.filter.Analyze(msg)

	// Debug: log suspicious messages
	if result.Score > 0 {
		log.Printf("Suspicious message from %s (%d) in chat %d: score=%d, reasons=%v, text=%q", displayName(msg.From), userID, chatID, result.Score, result.Reasons, messageText(msg))
	}

	// Always count the message regardless of outcome.
	defer b.store.IncrementMessageCount(userID)

	if result.Action == filter.ActionNone {
		log.Printf("Msg %d: score=%d below threshold, no action", msg.MessageID, result.Score)
		return
	}

	text := messageText(msg)
	username := displayName(msg.From)
	reason := fmt.Sprintf("score=%d reasons=[%s]", result.Score, strings.Join(result.Reasons, ", "))

	deleted := b.deleteMessage(chatID, msg.MessageID)
	if !deleted {
		log.Printf("Failed to delete message %d in chat %d before moderation, continuing", msg.MessageID, chatID)
	}

	b.store.SaveDeleted(chatID, msg.MessageID, userID, username, truncate(text, 300), reason, result.Score)

	switch result.Action {
	case filter.ActionWarn:
		b.sendTempWarning(chatID, msg.From)
		b.sendModLog(chatID, msg.MessageID, userID, username, text, reason, result.Score, result.Action)

	case filter.ActionMute:
		b.muteUser(chatID, userID, b.cfg.MuteDuration)
		b.sendModLog(chatID, msg.MessageID, userID, username, text, reason, result.Score, result.Action)

	case filter.ActionBan:
		b.banUser(chatID, userID)
		b.sendModLog(chatID, msg.MessageID, userID, username, text, reason, result.Score, result.Action)
	}

	if !deleted {
		if b.deleteMessage(chatID, msg.MessageID) {
			log.Printf("Deleted message %d in chat %d after moderation action", msg.MessageID, chatID)
		}
	}
}

// ── Callback handler ──────────────────────────────────────────────

// Callback data format:
//   res|<chatID>|<msgID>|<userID>      — restore (unban/unmute)
//   mut|<chatID>|<msgID>|<userID>      — mute 24 h (+ delete message msgID in chat)
//   ban|<chatID>|<msgID>|<userID>      — ban (+ delete message if still present)
//   mut|<chatID>|<userID>              — legacy mute without msgID
//   ban|<chatID>|<userID>              — legacy ban without msgID

func (b *Bot) handleCallback(cb *tgbotapi.CallbackQuery) {
	if cb.From == nil {
		return
	}
	log.Printf("Callback: data=%q from=%s (%d)", cb.Data, displayName(cb.From), cb.From.ID)

	parts := strings.Split(cb.Data, "|")
	if len(parts) < 3 {
		b.answerCallback(cb.ID, "❌ Неверный формат", true)
		return
	}

	action := parts[0]

	chatID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		b.answerCallback(cb.ID, "❌ Неверный chatID", true)
		return
	}

	moderatorName := displayName(cb.From)

	switch action {
	case "res":
		if len(parts) < 4 {
			b.answerCallback(cb.ID, "❌ Ошибка", true)
			return
		}
		msgID, e1 := strconv.Atoi(parts[2])
		targetUserID, e2 := strconv.ParseInt(parts[3], 10, 64)
		if e1 != nil || e2 != nil {
			b.answerCallback(cb.ID, "❌ Ошибка данных", true)
			return
		}

		deleted, hasDeleted := b.store.GetDeleted(chatID, msgID)
		if err := b.restoreUser(chatID, targetUserID); err != nil {
			b.answerCallback(cb.ID, "❌ Не удалось снять ограничения", true)
			return
		}

		restoredText := false
		if hasDeleted {
			restoredText = b.repostDeletedMessage(chatID, deleted)
		}

		userRef := fmt.Sprintf("id%d", targetUserID)
		if hasDeleted {
			userRef = escapeHTML(deleted.Username)
		}
		suffix := fmt.Sprintf("\n\n✅ <b>Восстановлен</b> %s — модератор %s", userRef, escapeHTML(moderatorName))
		if restoredText {
			suffix += "\n📨 Текст отправлен в чат"
		} else if hasDeleted && strings.TrimSpace(deleted.Text) != "" {
			suffix += "\n⚠️ Текст не удалось отправить в чат"
		}
		b.appendToLogMessage(cb, suffix)
		b.answerCallback(cb.ID, "✅ Пользователь восстановлен")

	case "mut":
		var targetMsgID int
		var targetUserID int64
		var e error
		if len(parts) >= 4 {
			targetMsgID, e = strconv.Atoi(parts[2])
			if e != nil {
				b.answerCallback(cb.ID, "❌ Ошибка данных", true)
				return
			}
			targetUserID, e = strconv.ParseInt(parts[3], 10, 64)
		} else {
			targetUserID, e = strconv.ParseInt(parts[2], 10, 64)
		}
		if e != nil {
			b.answerCallback(cb.ID, "❌ Ошибка данных", true)
			return
		}

		if targetMsgID != 0 {
			b.deleteMessage(chatID, targetMsgID)
		}
		b.muteUser(chatID, targetUserID, b.cfg.MuteDuration)

		suffix := fmt.Sprintf("\n\n🔇 <b>Замучен 24ч</b> модератором %s", escapeHTML(moderatorName))
		b.appendToLogMessage(cb, suffix)
		b.answerCallback(cb.ID, "🔇 Пользователь замучен")

	case "ban":
		var targetMsgID int
		var targetUserID int64
		var e error
		if len(parts) >= 4 {
			targetMsgID, e = strconv.Atoi(parts[2])
			if e != nil {
				b.answerCallback(cb.ID, "❌ Ошибка данных", true)
				return
			}
			targetUserID, e = strconv.ParseInt(parts[3], 10, 64)
		} else {
			targetUserID, e = strconv.ParseInt(parts[2], 10, 64)
		}
		if e != nil {
			b.answerCallback(cb.ID, "❌ Ошибка данных", true)
			return
		}

		if targetMsgID != 0 {
			b.deleteMessage(chatID, targetMsgID)
		}
		b.banUser(chatID, targetUserID)

		suffix := fmt.Sprintf("\n\n🚫 <b>Забанен</b> модератором %s", escapeHTML(moderatorName))
		b.appendToLogMessage(cb, suffix)
		b.answerCallback(cb.ID, "🚫 Пользователь забанен")

	default:
		b.answerCallback(cb.ID, "❌ Неизвестное действие", true)
	}

}

// ── Telegram API wrappers ─────────────────────────────────────────

func (b *Bot) isAdmin(chatID, userID int64) bool {
	if isAdmin, ok := b.store.GetAdminCache(chatID, userID); ok {
		return isAdmin
	}
	member, err := b.api.GetChatMember(tgbotapi.GetChatMemberConfig{
		ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
			ChatID: chatID,
			UserID: userID,
		},
	})
	if err != nil {
		log.Printf("GetChatMember(%d, %d): %v", chatID, userID, err)
		return false
	}
	admin := member.Status == "creator" || member.Status == "administrator"
	b.store.SetAdminCache(chatID, userID, admin)
	return admin
}

func (b *Bot) deleteMessage(chatID int64, msgID int) bool {
	if _, err := b.api.Request(tgbotapi.NewDeleteMessage(chatID, msgID)); err != nil {
		log.Printf("deleteMessage(%d, %d): %v", chatID, msgID, err)
		return false
	}
	return true
}

func (b *Bot) muteUser(chatID, userID int64, durationSec int) {
	until := time.Now().Add(time.Duration(durationSec) * time.Second)
	cfg := tgbotapi.RestrictChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		UntilDate: until.Unix(),
		Permissions: &tgbotapi.ChatPermissions{
			CanSendMessages:      false,
			CanSendMediaMessages: false,
			CanSendPolls:         false,
			CanSendOtherMessages: false,
		},
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("muteUser(%d, %d): %v", chatID, userID, err)
	}
	b.store.SetMuted(userID, until)
}

func (b *Bot) banUser(chatID, userID int64) {
	cfg := tgbotapi.BanChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		RevokeMessages: true,
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("banUser(%d, %d): %v", chatID, userID, err)
	}
	b.store.SetBanned(userID)
}

func (b *Bot) unbanUser(chatID, userID int64) {
	cfg := tgbotapi.UnbanChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		OnlyIfBanned: false, // also lifts restrictions
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("unbanUser(%d, %d): %v", chatID, userID, err)
	}
}

func (b *Bot) unmuteUser(chatID, userID int64) error {
	cfg := tgbotapi.RestrictChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		Permissions: &tgbotapi.ChatPermissions{
			CanSendMessages:       true,
			CanSendMediaMessages:  true,
			CanSendPolls:          true,
			CanSendOtherMessages:  true,
			CanAddWebPagePreviews: true,
		},
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("unmuteUser(%d, %d): %v", chatID, userID, err)
		return err
	}
	return nil
}

func (b *Bot) restoreUser(chatID, userID int64) error {
	b.unbanUser(chatID, userID)
	if err := b.unmuteUser(chatID, userID); err != nil {
		return err
	}
	b.store.ClearModeration(userID)
	return nil
}

func (b *Bot) repostDeletedMessage(chatID int64, d *storage.DeletedMessage) bool {
	if d == nil || strings.TrimSpace(d.Text) == "" {
		return false
	}
	body := fmt.Sprintf(
		"♻️ <b>Сообщение восстановлено модератором</b>\n"+
			"👤 %s\n\n%s",
		escapeHTML(d.Username),
		escapeHTML(d.Text),
	)
	msg := tgbotapi.NewMessage(chatID, body)
	msg.ParseMode = "HTML"
	if _, err := b.api.Send(msg); err != nil {
		log.Printf("repostDeletedMessage(%d): %v", chatID, err)
		return false
	}
	return true
}

func (b *Bot) sendTempWarning(chatID int64, from *tgbotapi.User) {
	name := displayName(from)
	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("⚠️ Сообщение от %s было удалено. Соблюдайте правила чата.", name),
	)
	sent, err := b.api.Send(msg)
	if err != nil {
		log.Printf("sendTempWarning: %v", err)
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		b.deleteMessage(chatID, sent.MessageID)
	}()
}

func (b *Bot) answerCallback(id, text string, showAlert ...bool) {
	cb := tgbotapi.NewCallback(id, text)
	if len(showAlert) > 0 && showAlert[0] {
		cb.ShowAlert = true
	}
	if _, err := b.api.Request(cb); err != nil {
		log.Printf("answerCallback: %v", err)
	}
}

// appendToLogMessage appends suffix to the existing log message text and
// removes the inline keyboard (action already taken).
func (b *Bot) appendToLogMessage(cb *tgbotapi.CallbackQuery, suffix string) {
	if cb.Message == nil {
		log.Printf("appendToLogMessage: callback has no message")
		return
	}
	logChatID := cb.Message.Chat.ID
	logMsgID := cb.Message.MessageID

	base := cb.Message.Text
	if base == "" {
		base = cb.Message.Caption
	}
	if base == "" {
		log.Printf("appendToLogMessage: empty log message text")
		b.removeLogKeyboard(logChatID, logMsgID)
		return
	}

	newText := escapeHTML(base) + suffix
	edit := tgbotapi.NewEditMessageText(logChatID, logMsgID, newText)
	edit.ParseMode = "HTML"
	empty := tgbotapi.NewInlineKeyboardMarkup()
	edit.ReplyMarkup = &empty

	if _, err := b.api.Request(edit); err != nil {
		log.Printf("appendToLogMessage: %v", err)
		b.removeLogKeyboard(logChatID, logMsgID)
	}
}

func (b *Bot) removeLogKeyboard(chatID int64, messageID int) {
	empty := tgbotapi.NewInlineKeyboardMarkup()
	edit := tgbotapi.NewEditMessageReplyMarkup(chatID, messageID, empty)
	if _, err := b.api.Request(edit); err != nil {
		log.Printf("removeLogKeyboard: %v", err)
	}
}

// ── Utility ───────────────────────────────────────────────────────

func messageText(msg *tgbotapi.Message) string {
	if msg.Text != "" {
		return msg.Text
	}
	return msg.Caption
}

func displayName(u *tgbotapi.User) string {
	if u == nil {
		return "unknown"
	}
	if u.UserName != "" {
		return "@" + u.UserName
	}
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name == "" {
		return fmt.Sprintf("id%d", u.ID)
	}
	return name
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
