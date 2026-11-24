package replace

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/ahocorasick"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/registry"
)

// Matcher replaces every mapped original in one left-to-right pass: at each
// position the longest original wins, and replaced text is never matched
// again (a replacement such as 10.0.0.1 can also be an original).
// Originals made only of letters, digits and "_" are replaced as whole
// tokens; others (hosts, paths, namespaces) as substrings. Organization
// labels (Replacement.Label) match in any case wherever no letter touches
// them (see LabelBoundary).
type Matcher struct {
	replacements []registry.Replacement
	token        []bool
	ac           *ahocorasick.Matcher
	// labels finds organization labels in the lower-cased text; ids index
	// replacements.
	labels   *ahocorasick.Matcher
	labelIDs []int
}

func New(replacements []registry.Replacement) *Matcher {
	m := &Matcher{}
	patterns := make([]string, 0, len(replacements))
	var labels []string
	for _, r := range replacements {
		if r.Original == "" {
			continue
		}
		m.replacements = append(m.replacements, r)
		m.token = append(m.token, identifierLike(r.Original))
		patterns = append(patterns, r.Original)
		if r.Label {
			m.labelIDs = append(m.labelIDs, len(m.replacements)-1)
			labels = append(labels, ASCIILower(r.Original))
		}
	}
	m.ac = ahocorasick.New(patterns)
	if len(labels) > 0 {
		m.labels = ahocorasick.New(labels)
	}
	return m
}

// ASCIILower lower-cases ASCII letters only, so byte offsets stay the same.
func ASCIILower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// LabelBoundary reports whether s[start:end] stands apart as an
// organization label: no letter touches it, or the case changes from lower
// to upper at the edge (camelCase: "acmeCorp", "myAcme"). Digits, "_", "-"
// and "." separate it.
func LabelBoundary(s string, start, end int) bool {
	if start > 0 {
		before, _ := utf8.DecodeLastRuneInString(s[:start])
		first, _ := utf8.DecodeRuneInString(s[start:])
		if unicode.IsLetter(before) && !(unicode.IsLower(before) && unicode.IsUpper(first)) {
			return false
		}
	}
	if end < len(s) {
		last, _ := utf8.DecodeLastRuneInString(s[:end])
		after, _ := utf8.DecodeRuneInString(s[end:])
		if unicode.IsLetter(after) && !(unicode.IsLower(last) && unicode.IsUpper(after)) {
			return false
		}
	}
	return true
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
		if m.replacements[id].Label {
			return // found by the case-insensitive pass below
		}
		if m.token[id] && !tokenBoundary(s, start, end, isIdent) {
			return
		}
		hits = append(hits, hit{start, end, id})
	})
	if m.labels != nil {
		m.labels.Each(ASCIILower(s), func(i, start, end int) {
			if LabelBoundary(s, start, end) {
				hits = append(hits, hit{start, end, m.labelIDs[i]})
			}
		})
	}
	if len(hits) == 0 {
		return s
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		if hits[i].end != hits[j].end {
			return hits[i].end > hits[j].end
		}
		return hits[i].id < hits[j].id
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
		if m.replacements[h.id].Label && h.end < len(s) && s[h.end] >= '0' && s[h.end] <= '9' {
			out.WriteByte('_') // "acme1" -> "Organization1_1", not "Organization11"
		}
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
