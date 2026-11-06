package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirFindsLeaksWithoutPrintingThem(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"host":"db1.secret.io:27017"}}`,                  // mapped fqdn left
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"filter":{"orders":"obfuscated string"}}}`,       // field name = collection: not a leak
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"servers":{"db1.secret.io:27017":{}}}}`,          // fqdn in a key
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"mail jane@corp.net card 4111 1111 1111 1111 from 8.8.8.8"}`, // detectors
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"q":"dc=Organization1,dc=com cn=user1"}}`,        // replacements: clean
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"q":"O=Acme"}}`,                                  // ldap
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"ok":"10.0.0.1 host1.example.com user1@example.com"}}`,
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"cursorid":{"$numberLong":"4111111111111111"}}}`, // not a card
	}
	if err := os.WriteFile(filepath.Join(dir, "mongod_obfuscated.log"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster_mapping.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	mapping := map[string]map[string]string{
		"fqdn":       {"db1.secret.io": "host1.example.com"},
		"collection": {"orders": "collection1"},
	}
	report, err := Dir(dir, Options{Mapping: mapping})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"mapped fqdn": 2, "email": 1, "card-number": 1, "public-ip": 1, "ldap": 1, "mapping-file": 1}
	for label, n := range want {
		if report.Counts[label] != n {
			t.Errorf("%s = %d, want %d (counts %v)", label, report.Counts[label], n, report.Counts)
		}
	}
	if report.Total != 7 {
		t.Errorf("total = %d, want 7: %v", report.Total, report.Counts)
	}
	var b strings.Builder
	report.Write(&b)
	for _, secret := range []string{"db1.secret.io", "jane@corp.net", "4111", "8.8.8.8", "Acme"} {
		if strings.Contains(b.String(), secret) {
			t.Errorf("report prints %q:\n%s", secret, b.String())
		}
	}
}
