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
			s = replaceIdentifierToken(s, r.Original, r.Value, isIdentifierRune)
			continue
		}
		s = strings.ReplaceAll(s, r.Original, r.Value)
	}
	return s
}

// ApplyName replaces originals in a file or directory name. It treats "_" as
// a separator, so "CS1_db01_mongod.log" has its host name "db01" replaced.
func (m *Matcher) ApplyName(s string) string {
	if m == nil || len(m.replacements) == 0 || s == "" {
		return s
	}
	for _, r := range m.replacements {
		if r.Original == "" || !strings.Contains(s, r.Original) {
			continue
		}
		if identifierLike(r.Original) {
			s = replaceIdentifierToken(s, r.Original, r.Value, isNameRune)
			continue
		}
		s = strings.ReplaceAll(s, r.Original, r.Value)
	}
	return s
}

func isNameRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func identifierLike(s string) bool {
	for _, r := range s {
		if !isIdentifierRune(r) {
			return false
		}
	}
	return true
}

func replaceIdentifierToken(s, old, replacement string, isIdent func(rune) bool) string {
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
		if tokenBoundary(s, idx, end, isIdent) {
			out.WriteString(s[start:idx])
			out.WriteString(replacement)
			start = end
			continue
		}
		out.WriteString(s[start:end])
		start = end
	}
}

func tokenBoundary(s string, start, end int, isIdent func(rune) bool) bool {
	return (start == 0 || !isIdent(rune(s[start-1]))) && (end == len(s) || !isIdent(rune(s[end])))
}

// TokenBoundary reports whether s[start:end] is a whole identifier token.
func TokenBoundary(s string, start, end int) bool {
	return tokenBoundary(s, start, end, isIdentifierRune)
}

// IdentifierLike reports whether s has only letters, digits and "_", so it is
// matched as a whole token rather than as a substring.
func IdentifierLike(s string) bool { return identifierLike(s) }

func isIdentifierRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
