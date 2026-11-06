package replace

import (
	"testing"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
)

// A replacement must never be replaced again: real 10.x addresses and the
// 10.x replacement addresses share one space.
func TestApplyDoesNotChainReplacements(t *testing.T) {
	reg := registry.New()
	reg.GetOrCreate("ip", "203.0.113.7") // -> 10.0.0.1
	reg.GetOrCreate("ip", "10.0.0.1")    // -> 10.0.0.2
	m := New(reg.Replacements())
	got := m.Apply("a=203.0.113.7 b=10.0.0.1")
	want := "a=" + reg.GetOrCreate("ip", "203.0.113.7") + " b=" + reg.GetOrCreate("ip", "10.0.0.1")
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
}
