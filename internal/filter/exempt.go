package filter

import "strings"

// applyExemptions lowers the score for clearly benign community messages.
func applyExemptions(scanText string, score int, reasons []string) (int, []string) {
	if isCasualReaction(scanText) {
		return 0, append(reasons, "casual_reaction_exempt")
	}
	if isSocialCompanionPost(scanText) {
		score -= 45
		reasons = append(reasons, "social_companion_exempt")
	}
	if score < 0 {
		score = 0
	}
	return score, reasons
}

func isCasualReaction(text string) bool {
	t := strings.TrimSpace(strings.ToLower(text))
	runes := []rune(t)
	if len(runes) == 0 || len(runes) > 30 {
		return false
	}
	block := []string{
		"₽", "руб", "работ", "ваканс", "зарабат", "usdt", "доход",
		"экзамен", "гибдд", "гимс", "шабаш", "скину", "налич",
	}
	for _, kw := range block {
		if strings.Contains(t, kw) {
			return false
		}
	}
	return true
}

func isSocialCompanionPost(text string) bool {
	t := strings.ToLower(text)
	if strings.Contains(t, "₽") || strings.Contains(t, "руб") || strings.Contains(t, "зарабат") ||
		strings.Contains(t, "работ") || strings.Contains(t, "ваканс") {
		return false
	}
	signals := 0
	if strings.Contains(t, "ищу компанию") || strings.Contains(t, "ищу компан") {
		signals++
	}
	if strings.Contains(t, "собирается") || strings.Contains(t, "концерт") || strings.Contains(t, "фестив") {
		signals++
	}
	if strings.Contains(t, "всем привет") || strings.Contains(t, "привет") {
		signals++
	}
	if strings.Contains(t, "лс") || strings.Contains(t, "личк") {
		signals++
	}
	if strings.Contains(t, "компан") && strings.Contains(t, "интересн") {
		signals++
	}
	return signals >= 2
}

// softenAction prevents ban when the score comes only from weak heuristics.
func softenAction(action Action, score int, reasons []string, thresholds configThresholds) Action {
	if action != ActionBan {
		return action
	}
	if hasBanTierReason(reasons) {
		return action
	}
	if !onlyWeakReasons(reasons) {
		return action
	}
	if score >= thresholds.Mute {
		return ActionMute
	}
	if score >= thresholds.Warn {
		return ActionWarn
	}
	return ActionNone
}

type configThresholds struct {
	Warn int
	Mute int
	Ban  int
}

func hasBanTierReason(reasons []string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, "ban_") {
			return true
		}
	}
	return false
}

func onlyWeakReasons(reasons []string) bool {
	weak := map[string]bool{
		"write":              true,
		"dm_me":              true,
		"dm_me2":             true,
		"write_ls":           true,
		"spam_reply":         true,
		"duplicate_message":  true,
		"social_companion_exempt": true,
		"casual_reaction_exempt":  true,
	}
	hasNonWeak := false
	for _, r := range reasons {
		if strings.HasPrefix(r, "×") {
			continue
		}
		if !weak[r] {
			hasNonWeak = true
			break
		}
	}
	return !hasNonWeak
}
