package replace

import (
	"strings"
	"testing"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
)

func TestApplyLongestFirstReplacementTable(t *testing.T) {
	m := New([]registry.Replacement{{Original: "customer.orders", Value: "database1.collection1"}, {Original: "customer", Value: "database1"}})
	got := m.Apply("ns customer.orders customer")
	if got != "ns database1.collection1 database1" {
		t.Fatalf("Apply() = %q", got)
	}
}

func BenchmarkApplyLargeMapping(b *testing.B) {
	var reps []registry.Replacement
	for i := 0; i < 1000; i++ {
		reps = append(reps, registry.Replacement{Original: "host" + strings.Repeat("x", i%20), Value: "h"})
	}
	m := New(reps)
	text := strings.Repeat("hostxxxxxxxxxxxxxxxxxxxx ", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Apply(text)
	}
}
