package replace

import (
	"strings"
	"unicode"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
)

type Matcher struct{ replacements []registry.Replacement }

func New(replacements []registry.Replacement) *Matcher {
	cp := append([]registry.Replacement(nil), replacements...)
	return &Matcher{replacements: cp}
}

func (m *Matcher) Apply(s string) string {
	if m == nil || len(m.replacements) == 0 || s == "" {
		return s
	}
	for _, r := range m.replacements {
		if r.Original == "" || !strings.Contains(s, r.Original) {
			continue
		}
		if identifierLike(r.Original) {
			s = replaceIdentifierToken(s, r.Original, r.Value)
			continue
		}
		s = strings.ReplaceAll(s, r.Original, r.Value)
	}
	return s
}

func identifierLike(s string) bool {
	for _, r := range s {
		if !isIdentifierRune(r) {
			return false
		}
	}
	return true
}

func replaceIdentifierToken(s, old, replacement string) string {
	var out strings.Builder
	start := 0
	for {
		idx := strings.Index(s[start:], old)
		if idx < 0 {
			out.WriteString(s[start:])
			return out.String()
		}
		idx += start
		end := idx + len(old)
		if tokenBoundary(s, idx, end) {
			out.WriteString(s[start:idx])
			out.WriteString(replacement)
			start = end
			continue
		}
		out.WriteString(s[start:end])
		start = end
	}
}

func tokenBoundary(s string, start, end int) bool {
	return (start == 0 || !isIdentifierRune(rune(s[start-1]))) && (end == len(s) || !isIdentifierRune(rune(s[end])))
}

func isIdentifierRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
