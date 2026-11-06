package registry

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHostNamesKeepSiteStructure(t *testing.T) {
	r := New()
	a := r.GetOrCreate("fqdn", "db7.phx.corp.com")
	b := r.GetOrCreate("fqdn", "db8.phx.corp.com")
	c := r.GetOrCreate("fqdn", "db9.gso.corp.com")
	k := r.GetOrCreate("fqdn", "mongo-rs0-0.mongo-rs0.psmdb.svc.cluster.local")
	suffix := func(s string) string { return s[strings.Index(s, ".")+1:] }
	if suffix(a) != suffix(b) || suffix(a) == suffix(c) {
		t.Fatalf("site structure lost: %s %s %s", a, b, c)
	}
	if !strings.HasSuffix(a, ".example.com") || !strings.HasSuffix(k, ".svc.cluster.local") {
		t.Fatalf("unexpected forms: %s %s", a, k)
	}
	if strings.Contains(k, "psmdb") || strings.Contains(k, "mongo-rs0") {
		t.Fatalf("kubernetes names kept: %s", k)
	}
	// the short name of a host maps like the first label of its FQDN
	if short := r.GetOrCreate("hostname", "mongo-rs0-0"); !strings.HasPrefix(k, short+".") {
		t.Fatalf("short name %s does not match %s", short, k)
	}
	// a short name seen after its FQDN keeps the FQDN's host number
	if short := r.GetOrCreate("hostname", "db7"); !strings.HasPrefix(a, short+".") {
		t.Fatalf("short name %s does not match %s", short, a)
	}
	// labels are not replaced on their own
	for _, rep := range r.Replacements() {
		if rep.Original == "phx" || rep.Original == "psmdb" {
			t.Fatalf("label %q replaced on its own", rep.Original)
		}
	}
}

func TestIPsKeepSubnets(t *testing.T) {
	r := New()
	a := r.GetOrCreate("ip", "203.0.113.7")
	b := r.GetOrCreate("ip", "203.0.113.9")
	c := r.GetOrCreate("ip", "172.20.5.9")
	if a[:strings.LastIndex(a, ".")] != b[:strings.LastIndex(b, ".")] || !strings.HasSuffix(a, ".7") || !strings.HasSuffix(b, ".9") {
		t.Fatalf("subnet or host octet lost: %s %s", a, b)
	}
	if !strings.HasPrefix(a, "198.18.") || !strings.HasPrefix(c, "10.") {
		t.Fatalf("public/private class lost: %s %s", a, c)
	}
	// a later run continues from the saved mapping without collisions
	path := filepath.Join(t.TempDir(), "m.json")
	if err := r.Write(path); err != nil {
		t.Fatal(err)
	}
	r2 := New()
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := r2.GetOrCreate("ip", "203.0.113.200"); got[:strings.LastIndex(got, ".")] != a[:strings.LastIndex(a, ".")] {
		t.Fatalf("loaded mapping lost the subnet: %s vs %s", got, a)
	}
	if d := r2.GetOrCreate("ip", "198.51.100.1"); d[:strings.LastIndex(d, ".")] == a[:strings.LastIndex(a, ".")] {
		t.Fatalf("new subnet reuses an existing one: %s", d)
	}
}

func TestOneCategoryPerValue(t *testing.T) {
	r := New()
	c1, c2 := NewCollector(), NewCollector()
	c1.Register("data", "rs-prod-5")
	c2.Register("replset", "rs-prod-5")
	r.MergeCollectors([]*Collector{c1, c2})
	reps := r.Replacements()
	if len(reps) != 1 || !strings.HasPrefix(reps[0].Value, "replset") {
		t.Fatalf("replacements = %+v", reps)
	}
}
