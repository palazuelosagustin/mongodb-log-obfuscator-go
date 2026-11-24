package replace

import (
	"testing"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/registry"
)

func TestApplyOrgLabels(t *testing.T) {
	m := New([]registry.Replacement{
		{Original: "db1.acme.com", Value: "host1.domain1.example.com"},
		{Original: "acme_orders", Value: "collection1"},
		{Original: "acme", Value: "Organization1", Label: true},
	})
	cases := map[string]string{
		"appd-mongo-dbagent-acme1-1-prod": "appd-mongo-dbagent-Organization1_1-1-prod",
		"ACME_reports for Acme-EU":        "Organization1_reports for Organization1-EU",
		"see wiki/acme.":                  "see wiki/Organization1.",
		"acmeCorp and myAcme":             "Organization1Corp and myOrganization1",
		"AcMe and SecretAcme":             "Organization1 and SecretOrganization1",
		"macmed academy Acmes ACMEreport": "macmed academy Acmes ACMEreport",
		"connect db1.acme.com":            "connect host1.domain1.example.com", // longer original wins
		"find acme_orders":                "find collection1",
	}
	for in, want := range cases {
		if got := m.Apply(in); got != want {
			t.Errorf("Apply(%q) = %q, want %q", in, got, want)
		}
	}
	if got := m.ApplyName("CS1_acme_mongod.log"); got != "CS1_Organization1_mongod.log" {
		t.Errorf("ApplyName = %q", got)
	}
}
