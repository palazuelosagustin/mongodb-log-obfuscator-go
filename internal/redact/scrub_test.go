package redact

import "testing"

func TestScrubTextKeepsUUIDs(t *testing.T) {
	// Each UUID has a run of all-digit groups that passes the Luhn check, so
	// the card rule used to rewrite part of it.
	for _, digits := range []string{"61949369-6126-4783", "12340008-1234-1234", "1234-123456780002"} {
		if !LuhnCard(digits) {
			t.Fatalf("test data: %s must pass the Luhn check", digits)
		}
	}
	cases := []struct{ in, want string }{
		{"61949369-6126-4783-8c4e-d2211f649f53", "61949369-6126-4783-8c4e-d2211f649f53"},
		{"12340008-1234-1234-abcd-0123456789ab", "12340008-1234-1234-abcd-0123456789ab"},
		{"abcdef01-abcd-ef01-1234-123456780002", "abcdef01-abcd-ef01-1234-123456780002"},
		{"index build 61949369-6126-4783-8C4E-D2211F649F53 failed", "index build 61949369-6126-4783-8C4E-D2211F649F53 failed"},
		// card numbers are still replaced, also next to a UUID
		{"card 4111 1111 1111 1111 build 12340008-1234-1234-abcd-0123456789ab", "card obfuscated-number build 12340008-1234-1234-abcd-0123456789ab"},
		{"4111-1111-1111-1111", "obfuscated-number"},
	}
	for _, c := range cases {
		got, _ := ScrubText(c.in)
		if got != c.want {
			t.Errorf("ScrubText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
