package replace

import (
	"sort"
	"strings"
	"unicode"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/ahocorasick"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
)

// Matcher replaces every mapped original in one left-to-right pass: at each
// position the longest original wins, and replaced text is never matched
// again (a replacement such as 10.0.0.1 can also be an original).
// Originals made only of letters, digits and "_" are replaced as whole
// tokens; others (hosts, paths, namespaces) as substrings.
type Matcher struct {
	replacements []registry.Replacement
	token        []bool
	ac           *ahocorasick.Matcher
}

func New(replacements []registry.Replacement) *Matcher {
	m := &Matcher{}
	patterns := make([]string, 0, len(replacements))
	for _, r := range replacements {
		if r.Original == "" {
			continue
		}
		m.replacements = append(m.replacements, r)
		m.token = append(m.token, identifierLike(r.Original))
		patterns = append(patterns, r.Original)
	}
	m.ac = ahocorasick.New(patterns)
	return m
}

func (m *Matcher) Apply(s string) string {
	return m.apply(s, isIdentifierRune)
}

// ApplyName replaces originals in a file or directory name. It treats "_" as
// a separator, so "CS1_db01_mongod.log" has its host name "db01" replaced.
func (m *Matcher) ApplyName(s string) string {
	return m.apply(s, isNameRune)
}

type hit struct{ start, end, id int }

func (m *Matcher) apply(s string, isIdent func(rune) bool) string {
	if m == nil || len(m.replacements) == 0 || s == "" {
		return s
	}
	var hits []hit
	m.ac.Each(s, func(id, start, end int) {
		if m.token[id] && !tokenBoundary(s, start, end, isIdent) {
			return
		}
		hits = append(hits, hit{start, end, id})
	})
	if len(hits) == 0 {
		return s
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end > hits[j].end
	})
	var out strings.Builder
	out.Grow(len(s))
	pos := 0
	for _, h := range hits {
		if h.start < pos {
			continue
		}
		out.WriteString(s[pos:h.start])
		out.WriteString(m.replacements[h.id].Value)
		pos = h.end
	}
	out.WriteString(s[pos:])
	return out.String()
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
