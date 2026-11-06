package version

import (
	"strings"
	"testing"
)

func TestLong(t *testing.T) {
	defer func(v, c, d string) { Version, Commit, Date = v, c, d }(Version, Commit, Date)

	Version, Commit, Date = "v0.1.0", "0123456789abcdef", "2026-11-06T12:00:00Z"
	if got, want := Long("mongodb-log-obfuscator-go"), "mongodb-log-obfuscator-go v0.1.0 (0123456, 2026-11-06T12:00:00Z)"; got != want {
		t.Fatalf("Long() = %q, want %q", got, want)
	}
	if got := String(); got != "v0.1.0" {
		t.Fatalf("String() = %q", got)
	}

	Version, Commit, Date = "dev", "", ""
	if got := String(); !strings.HasPrefix(got, "dev") {
		t.Fatalf("source build String() = %q, want dev...", got)
	}
}
