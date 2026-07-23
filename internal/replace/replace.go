package replace

import (
	"strings"

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
		if r.Original != "" && strings.Contains(s, r.Original) {
			s = strings.ReplaceAll(s, r.Original, r.Value)
		}
	}
	return s
}
