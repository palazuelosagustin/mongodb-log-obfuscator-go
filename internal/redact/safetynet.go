package redact

import (
	"regexp"
	"sort"
	"strings"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/ahocorasick"
)

// Top-level domains accepted for host names found in free text. Free text
// also holds Java class names (java.util.concurrent.ThreadPoolExecutor),
// versions (4.1.13.final) and build hosts; host fields are trusted as is.
var hostTLDs = set("com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "biz", "info", "local", "internal", "corp", "lan", "intra", "intranet", "cloud", "app", "dev", "ai", "me", "tech", "online", "site", "xyz", "group", "bank", "finance", "insurance", "health", "global", "eu", "us", "uk", "de", "fr", "es", "it", "nl", "be", "ch", "at", "se", "no", "dk", "fi", "pl", "pt", "ie", "ca", "au", "nz", "jp", "cn", "in", "br", "mx", "ar", "cl", "za", "sg", "hk", "tw", "kr", "ru", "il", "ae", "sa", "tr", "id", "my", "th", "vn", "ph", "lu", "cz", "gr", "ro", "hu")

// Public vendor domains that appear in build and version strings.
var vendorDomains = []string{"redhat.com", "mongodb.com", "mongodb.org", "percona.com", "ubuntu.com", "debian.org", "centos.org", "fedoraproject.org", "github.com", "golang.org", "openssl.org"}

// PlausibleHostName reports whether a dotted name found in free text is
// likely a host name: lowercase, a known top-level domain, not a vendor.
func PlausibleHostName(name string) bool {
	if strings.ToLower(name) != name {
		return false
	}
	labels := strings.Split(name, ".")
	if _, ok := hostTLDs[labels[len(labels)-1]]; !ok {
		return false
	}
	for _, d := range vendorDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return false
		}
	}
	return true
}

// Placeholders written by the safety net.
const (
	NetHost  = "obfuscated-host"
	NetIP    = "192.0.2.1" // TEST-NET-1, never routed
	NetEmail = "obfuscated@example.com"
	NetPath  = "/obfuscated/path"
)

var (
	netEmail = regexp.MustCompile(`\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b`)
	netIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	netFQDN  = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b`)
	// an absolute path at the start or after a separator, not "//host"
	netPath = regexp.MustCompile(`(?:^|[\s"'=(,:\[])(/[A-Za-z0-9._~@%+=,-][A-Za-z0-9._~@%+=,/-]*)`)
)

// System and default MongoDB paths say nothing about the customer.
var keptPathPrefixes = []string{"/proc/", "/sys/", "/dev/", "/etc/", "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/tmp/", "/run/", "/var/run/", "/var/lib/mongo", "/var/log/mongo", "/obfuscated/", "/data/db", "/data/configdb"}

// Keys whose strings are fixed vocabulary, ids or timestamps.
var netSkipKeys = set("s", "c", "id", "ctx", "msg", "codeName", "planSummary", "type", "op", "stage", "$date", "$oid", "$uuid", "$numberLong", "$numberInt", "$numberDouble", "$numberDecimal", "base64", "subType", "queryHash", "planCacheKey", "queryShapeHash", "planCacheShapeHash")

// SafetyNet replaces what still looks like a host name, IP address, email or
// customer path in a string after the mapping: names the discovery did not
// find. Text produced by the mapping (replacements) is never touched, and
// only the matched part is replaced, so messages stay readable.
type SafetyNet struct {
	replacements *ahocorasick.Matcher
}

// NewSafetyNet takes the replacement values of the mapping.
func NewSafetyNet(replacements []string) *SafetyNet {
	return &SafetyNet{replacements: ahocorasick.New(replacements)}
}

type span struct{ start, end int }

// Apply returns s with remaining names replaced, and how many.
func (n *SafetyNet) Apply(key, s string) (string, int) {
	if n == nil || s == "" || !strings.ContainsAny(s, ".@/") {
		return s, 0
	}
	if _, skip := netSkipKeys[key]; skip {
		return s, 0
	}
	var protected []span
	n.replacements.Each(s, func(_, start, end int) {
		protected = append(protected, span{start, end})
	})
	inside := func(start, end int) bool {
		for _, p := range protected {
			if start >= p.start && end <= p.end {
				return true
			}
		}
		return false
	}
	type edit struct {
		start, end int
		with       string
	}
	var edits []edit
	add := func(start, end int, with string) {
		if inside(start, end) {
			return
		}
		for _, e := range edits {
			if start < e.end && end > e.start {
				return // overlaps an earlier, wider match
			}
		}
		edits = append(edits, edit{start, end, with})
	}
	for _, m := range netEmail.FindAllStringIndex(s, -1) {
		if !strings.HasSuffix(strings.ToLower(s[m[0]:m[1]]), "example.com") {
			add(m[0], m[1], NetEmail)
		}
	}
	for _, m := range netIPv4.FindAllStringIndex(s, -1) {
		ip := s[m[0]:m[1]]
		if strings.HasPrefix(ip, "127.") || ip == "0.0.0.0" || ip == NetIP || !validIPv4(ip) {
			continue
		}
		add(m[0], m[1], NetIP)
	}
	for _, m := range netFQDN.FindAllStringIndex(s, -1) {
		name := s[m[0]:m[1]]
		if strings.HasSuffix(name, ".example.com") || name == "example.com" || !PlausibleHostName(name) {
			continue
		}
		if m[0] > 0 && (s[m[0]-1] == '@' || s[m[0]-1] == '/') {
			continue // the domain of an email, or part of a path
		}
		add(m[0], m[1], NetHost)
	}
	for _, m := range netPath.FindAllStringSubmatchIndex(s, -1) {
		start, end := m[2], m[3]
		path := s[start:end]
		if strings.Count(path, "/") < 2 || keptPath(path) {
			continue
		}
		add(start, end, NetPath)
	}
	if len(edits) == 0 {
		return s, 0
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var b strings.Builder
	pos := 0
	for _, e := range edits {
		b.WriteString(s[pos:e.start])
		b.WriteString(e.with)
		pos = e.end
	}
	b.WriteString(s[pos:])
	return b.String(), len(edits)
}

func keptPath(p string) bool {
	for _, k := range keptPathPrefixes {
		if strings.HasPrefix(p, k) {
			return true
		}
	}
	return false
}

func validIPv4(s string) bool {
	for _, part := range strings.Split(s, ".") {
		if len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		v := 0
		for _, c := range part {
			v = v*10 + int(c-'0')
		}
		if v > 255 {
			return false
		}
	}
	return true
}
