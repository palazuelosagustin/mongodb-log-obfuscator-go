package registry

import "testing"

func TestOrgLabelOf(t *testing.T) {
	cases := map[string]string{
		"db1.acme.com":             "acme",
		"acme.com":                 "acme",
		"ACME.COM.":                "acme",
		"app7.prod.globex.co.uk":   "globex",
		"x.initech.com.au":         "initech",
		"cl0.abcd.mongodb.net":     "", // platform suffix
		"ip-10-0-0-1.ec2.internal": "",
		"svc.cluster.local":        "",
		"db1.corp.com":             "", // generic word
		"db1.ibm.com":              "", // shorter than 4 letters
		"db1.acme-eu.com":          "", // not letters only
		"db1.percona.com":          "",
		"co.uk":                    "",
		"localhost":                "",
	}
	for name, want := range cases {
		if got := orgLabelOf(name); got != want {
			t.Errorf("orgLabelOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestMergeRegistersDomainOrgLabels(t *testing.T) {
	c := NewCollector()
	c.Register("fqdn", "db1.acme.com")
	c.Register("domain", "acme.com")
	c.Register("fqdn", "web.initech.co.uk")
	c.Register("fqdn", "umbrella.globex.com") // host label "umbrella" is a hostname
	c.Register("fqdn", "db2.umbrella.com")
	c.Register("org", "Globex") // from an LDAP name: one org per name
	r := New()
	r.MergeCollectors([]*Collector{c})
	org := r.Categories["org"]
	if org["acme"] == "" || org["initech"] == "" {
		t.Errorf("domain labels not registered: %v", org)
	}
	if _, ok := org["globex"]; ok {
		t.Errorf("globex registered twice: %v", org)
	}
	if _, ok := org["umbrella"]; ok || r.Categories["hostname"]["umbrella"] == "" {
		t.Errorf("umbrella should stay a host name: org %v", org)
	}
	labels := map[string]bool{}
	for _, rep := range r.ReplacementsFor("org") {
		labels[rep.Original] = rep.Label
	}
	if !labels["acme"] || !labels["Globex"] {
		t.Errorf("org names of 4+ letters should match as labels: %v", labels)
	}
	// idempotent across batches
	before := len(org)
	r.MergeCollectors([]*Collector{c})
	if len(r.Categories["org"]) != before {
		t.Errorf("second merge added org names: %v", r.Categories["org"])
	}
}

func TestOrgLabel(t *testing.T) {
	for s, want := range map[string]bool{"acme": true, "SecretCorp": true, "ibm": false, "SecretCorp Inc": false, "acme1": false} {
		if OrgLabel(s) != want {
			t.Errorf("OrgLabel(%q) = %v", s, !want)
		}
	}
}
