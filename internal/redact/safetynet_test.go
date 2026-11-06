package redact

import "testing"

func TestSafetyNetReplacesUnknownNamesOnly(t *testing.T) {
	n := NewSafetyNet([]string{"host2.zone1.domain1.example.com", "198.18.0.7", "/obfuscated/path1", "10.0.1.9"})
	cases := []struct{ key, in, want string }{
		{"error", "connect to db9.unknown-corp.io:27017 from 198.51.100.77 failed",
			"connect to obfuscated-host:27017 from 192.0.2.1 failed"},
		{"error", "mail bob@corp.net about /data/customer1/file.wt",
			"mail obfuscated@example.com about /obfuscated/path"},
		{"error", "host2.zone1.domain1.example.com:27017 from 198.18.0.7 and 10.0.1.9 in /obfuscated/path1/x",
			"host2.zone1.domain1.example.com:27017 from 198.18.0.7 and 10.0.1.9 in /obfuscated/path1/x"},
		{"error", "at java.util.concurrent.ThreadPoolExecutor.run (/proc/self/mountinfo, /var/lib/mongo/x)",
			"at java.util.concurrent.ThreadPoolExecutor.run (/proc/self/mountinfo, /var/lib/mongo/x)"},
		{"uri", "mongodb://host2.zone1.domain1.example.com:27017/database1?authSource=admin",
			"mongodb://host2.zone1.domain1.example.com:27017/database1?authSource=admin"},
		{"error", "127.0.0.1 and 0.0.0.0 and kernel 4.18.0-80.el8.x86_64", "127.0.0.1 and 0.0.0.0 and kernel 4.18.0-80.el8.x86_64"},
		{"msg", "db9.unknown-corp.io", "db9.unknown-corp.io"}, // fixed vocabulary keys are skipped
		{"error", "mongodb.org build x86-64.build.eng.rdu2.redhat.com", "mongodb.org build x86-64.build.eng.rdu2.redhat.com"},
	}
	for _, c := range cases {
		if got, _ := n.Apply(c.key, c.in); got != c.want {
			t.Errorf("Apply(%q, %q)\n got %q\nwant %q", c.key, c.in, got, c.want)
		}
	}
}
