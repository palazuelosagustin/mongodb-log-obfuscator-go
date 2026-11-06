package redact

import (
	"regexp"
	"strings"
)

// NumberPlaceholder replaces card-like numbers found in free text.
const NumberPlaceholder = "obfuscated-number"

var reDupKey = regexp.MustCompile(`dup key: \{[^{}]*\}`)
var reDupKeyValue = regexp.MustCompile(`(\b[\w.$]+): ("(?:[^"\\]|\\.)*"|[^,}]+)`)
var reCardLike = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

// ScrubText removes values that free text (error messages, comments, log
// prefixes) can carry and the mapping cannot know in advance: the key values
// of duplicate-key errors and card-like numbers (13-19 digits passing the
// Luhn check). Field names are kept. It returns the text and the number of
// values replaced.
func ScrubText(s string) (string, int) {
	count := 0
	if strings.Contains(s, "dup key: {") {
		s = reDupKey.ReplaceAllStringFunc(s, func(m string) string {
			inner := m[len("dup key: {") : len(m)-1]
			inner = reDupKeyValue.ReplaceAllStringFunc(inner, func(kv string) string {
				count++
				sub := reDupKeyValue.FindStringSubmatch(kv)
				return sub[1] + `: "` + Token(strings.Trim(sub[2], `"`)) + `"`
			})
			return "dup key: {" + inner + "}"
		})
	}
	if digitCount(s) >= 13 {
		s = reCardLike.ReplaceAllStringFunc(s, func(m string) string {
			if !LuhnCard(m) {
				return m
			}
			count++
			return NumberPlaceholder
		})
	}
	return s, count
}

// LuhnCard reports whether s (digits with optional spaces or dashes) has
// 13-19 digits and passes the Luhn checksum used by payment card numbers.
func LuhnCard(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = append(digits, int(r-'0'))
		case r == ' ' || r == '-':
		default:
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if (len(digits)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func digitCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}
