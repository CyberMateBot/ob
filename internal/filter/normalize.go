package filter

import (
	"strings"
	"unicode"
)

// normalizeFilterText removes combining marks and invisible characters used to evade
// keyword filters (e.g. "О̷ф̷и̷ц̷и̷а̷л̷ь̷н̷о̷" → "официально").
func normalizeFilterText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
			continue
		case r == '\u200b', r == '\u200c', r == '\u200d', r == '\ufeff', r == '\u00ad', r == '\u034f':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// combiningMarkRatio returns the share of combining marks among letters (0 if no letters).
func combiningMarkRatio(s string) float64 {
	var letters, marks int
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
			marks++
		case unicode.IsLetter(r):
			letters++
		}
	}
	if letters == 0 {
		return 0
	}
	return float64(marks) / float64(letters)
}
