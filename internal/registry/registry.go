package registry

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Replacement struct {
	Original string
	Value    string
}

type Registry struct {
	Categories map[string]map[string]string
	Counters   map[string]int
	// EqualityKey (hex) keys the hashes of --keep-equality; saved in the
	// mapping so later runs hash the same values the same way.
	EqualityKey string
}

const equalitySection = "_equality"

type Collector struct {
	Values map[string]map[string]struct{}
}

var categories = []string{"hostname", "fqdn", "domain", "ip", "database", "collection", "replset", "shard", "user", "email", "path", "cert_subject", "org", "location", "java_class", "appname", "data", "zone", "hostlabel", "subnet_private", "subnet_public"}

// Hidden categories build replacements (domain labels, short host labels,
// /24 subnets) and are kept in the mapping so later runs stay consistent,
// but they are not replaced on their own: a label such as "phx" is only
// replaced as part of a host or domain name.
var hidden = map[string]bool{"zone": true, "hostlabel": true, "subnet_private": true, "subnet_public": true}

// Hidden reports categories that are not searched or replaced on their own.
func Hidden(category string) bool { return hidden[category] }

func New() *Registry {
	r := &Registry{Categories: map[string]map[string]string{}, Counters: map[string]int{}}
	for _, cat := range categories {
		r.Categories[cat] = map[string]string{}
	}
	return r
}

func NewCollector() *Collector { return &Collector{Values: map[string]map[string]struct{}{}} }

func (c *Collector) Register(category, value string) {
	if value == "" || len(value) < 2 {
		return
	}
	if category == "hostname" && len(value) < 4 {
		return
	}
	if c.Values[category] == nil {
		c.Values[category] = map[string]struct{}{}
	}
	c.Values[category][value] = struct{}{}
}

// priority decides the category of a value discovered in several: a replica
// set name seen in free text is still a replica set name.
var priority = []string{"replset", "shard", "database", "collection", "user", "email", "cert_subject", "fqdn", "hostname", "domain", "ip", "path", "appname", "org", "location", "java_class", "data"}

func (r *Registry) MergeCollectors(collectors []*Collector) {
	for _, cat := range priority {
		values := map[string]struct{}{}
		for _, c := range collectors {
			for value := range c.Values[cat] {
				values[value] = struct{}{}
			}
		}
		sorted := make([]string, 0, len(values))
		for value := range values {
			if r.categoryOf(value) == "" || r.categoryOf(value) == cat {
				sorted = append(sorted, value)
			}
		}
		sort.Strings(sorted)
		for _, value := range sorted {
			r.GetOrCreate(cat, value)
		}
	}
}

// categoryOf returns the category value is mapped in, or "".
func (r *Registry) categoryOf(value string) string {
	for _, cat := range priority {
		if _, ok := r.Categories[cat][value]; ok {
			return cat
		}
	}
	return ""
}

func (r *Registry) GetOrCreate(category, original string) string {
	if original == "" {
		return original
	}
	if r.Categories[category] == nil {
		r.Categories[category] = map[string]string{}
	}
	if replacement, ok := r.Categories[category][original]; ok {
		return replacement
	}
	var replacement string
	switch category {
	case "fqdn":
		replacement = r.fqdnReplacement(original)
	case "domain":
		if keptSuffix(original) {
			return original
		}
		replacement = r.domainReplacement(original)
	case "ip":
		replacement = r.ipReplacement(original)
	case "hostname":
		if label, ok := r.Categories["hostlabel"][original]; ok {
			replacement = label // first seen as the first label of an FQDN
			break
		}
		r.Counters[category]++
		replacement = template(category, r.Counters[category])
	default:
		r.Counters[category]++
		replacement = template(category, r.Counters[category])
	}
	r.Categories[category][original] = replacement
	return replacement
}

// Generic DNS suffixes kept as they are: they name a platform, not a
// customer (Kubernetes services, cloud provider zones).
var keptSuffixes = []string{"svc.cluster.local", "cluster.local", "compute.internal", "ec2.internal", "amazonaws.com", "mongodb.net", "azure.com", "cloudapp.net", "googleapis.com"}

func keptSuffix(domain string) bool {
	for _, k := range keptSuffixes {
		if domain == k {
			return true
		}
	}
	return false
}

// fqdnReplacement keeps the structure of a host name: the first label maps
// like a short host name (db7 and db7.phx.corp.com stay the same host), the
// rest like a domain, so hosts of one site or namespace share a suffix.
func (r *Registry) fqdnReplacement(fqdn string) string {
	first, parent, ok := strings.Cut(fqdn, ".")
	if !ok || first == "" || parent == "" {
		r.Counters["hostname"]++
		return template("fqdn", r.Counters["hostname"])
	}
	return r.hostLabel(first) + "." + r.GetOrCreate("domain", parent)
}

// hostLabel maps the first label of a host name. Labels of 4+ characters are
// host names replaced everywhere; shorter ones ("db") only inside names.
func (r *Registry) hostLabel(label string) string {
	if len(label) >= 4 {
		return r.GetOrCreate("hostname", label)
	}
	if repl, ok := r.Categories["hostlabel"][label]; ok {
		return repl
	}
	r.Counters["hostname"]++
	repl := template("hostname", r.Counters["hostname"])
	r.Categories["hostlabel"][label] = repl
	return repl
}

// domainReplacement maps corp.com to domainN.example.com and each further
// label to zoneN: phx.corp.com -> zone1.domain1.example.com.
func (r *Registry) domainReplacement(domain string) string {
	first, rest, _ := strings.Cut(domain, ".")
	if strings.Count(domain, ".") < 2 && !keptSuffix(rest) {
		r.Counters["domain"]++
		return template("domain", r.Counters["domain"])
	}
	zone, ok := r.Categories["zone"][first]
	if !ok {
		r.Counters["zone"]++
		zone = "zone" + strconv.Itoa(r.Counters["zone"])
		r.Categories["zone"][first] = zone
	}
	return zone + "." + r.GetOrCreate("domain", rest)
}

// ipReplacement maps each /24 to its own replacement /24 and keeps the last
// octet, so addresses of one subnet stay together. Private addresses map to
// 10.0.0.0/8, public ones to 198.18.0.0/15 and then 100.64.0.0/10 (reserved
// ranges that are never routed).
func (r *Registry) ipReplacement(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		r.Counters["ip"]++
		return template("ip", r.Counters["ip"])
	}
	b := addr.As4()
	prefix := fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2])
	cat := "subnet_public"
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || (b[0] == 100 && b[1]&0xc0 == 64) {
		cat = "subnet_private"
	}
	sub, ok := r.Categories[cat][prefix]
	if !ok {
		used := r.usedSubnets()
		for {
			r.Counters[cat]++
			sub = subnetName(cat == "subnet_private", r.Counters[cat])
			if !used[sub] {
				break
			}
		}
		r.Categories[cat][prefix] = sub
	}
	return fmt.Sprintf("%s.%d", sub, b[3])
}

func subnetName(private bool, n int) string {
	if private {
		return fmt.Sprintf("10.%d.%d", (n>>8)&255, n&255)
	}
	n--
	if n < 512 {
		return fmt.Sprintf("198.%d.%d", 18+(n>>8), n&255)
	}
	n -= 512
	return fmt.Sprintf("100.%d.%d", 64+((n>>8)&63), n&255)
}

// usedSubnets are the /24s of every IP replacement so far, including ones
// loaded from a mapping written before subnets were kept.
func (r *Registry) usedSubnets() map[string]bool {
	used := map[string]bool{}
	for _, repl := range r.Categories["ip"] {
		if i := strings.LastIndexByte(repl, '.'); i > 0 {
			used[repl[:i]] = true
		}
	}
	for _, cat := range []string{"subnet_private", "subnet_public"} {
		for _, sub := range r.Categories[cat] {
			used[sub] = true
		}
	}
	return used
}

func template(category string, n int) string {
	num := strconv.Itoa(n)
	switch category {
	case "hostname":
		return "host" + num
	case "fqdn":
		return "host" + num + ".example.com"
	case "domain":
		return "domain" + num + ".example.com"
	case "ip":
		return "10." + strconv.Itoa((n>>16)&0xff) + "." + strconv.Itoa((n>>8)&0xff) + "." + strconv.Itoa(n&0xff)
	case "database":
		return "database" + num
	case "collection":
		return "collection" + num
	case "replset":
		return "replset" + num
	case "shard":
		return "shard" + num
	case "user":
		return "user" + num
	case "email":
		return "user" + num + "@example.com"
	case "path":
		return "/obfuscated/path" + num
	case "cert_subject":
		return "CN=cert" + num + ".example.com,O=Organization,L=City,ST=State,C=XX"
	case "org":
		return "Organization" + num
	case "location":
		return "Location" + num
	case "java_class":
		return "com.example.app.Class" + num
	case "appname":
		return "app" + num
	default:
		return "data_" + num
	}
}

func (r *Registry) Replacements() []Replacement {
	return r.ReplacementsFor(categories...)
}

// NetworkAndPathCategories are the categories replaced inside JSON/BSON keys:
// hosts, IPs and paths appear as keys (topology descriptions, connection
// pools, socket paths), field names otherwise stay as they are.
var NetworkAndPathCategories = []string{"hostname", "fqdn", "domain", "ip", "path", "email"}

// ReplacementsFor returns the replacements of the given categories, longest
// original first.
func (r *Registry) ReplacementsFor(cats ...string) []Replacement {
	want := map[string]bool{}
	for _, cat := range cats {
		want[cat] = true
	}
	var out []Replacement
	seen := map[string]bool{}
	for _, cat := range priority { // one replacement per original
		for original, replacement := range r.Categories[cat] {
			if seen[original] {
				continue
			}
			seen[original] = true
			if want[cat] {
				out = append(out, Replacement{Original: original, Value: replacement})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Original) == len(out[j].Original) {
			return out[i].Original < out[j].Original
		}
		return len(out[i].Original) > len(out[j].Original)
	})
	return out
}

func (r *Registry) Report() map[string]map[string]string {
	out := map[string]map[string]string{}
	if r.EqualityKey != "" {
		out[equalitySection] = map[string]string{"key": r.EqualityKey}
	}
	for _, cat := range categories {
		if len(r.Categories[cat]) == 0 {
			continue
		}
		out[cat] = r.Categories[cat]
	}
	return out
}

func (r *Registry) Write(path string) error {
	b, err := json.MarshalIndent(r.Report(), "", "  ")
	if err != nil {
		return err
	}
	// The mapping reverses the obfuscation: only the owner may read it.
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (r *Registry) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var mapping map[string]map[string]string
	if err := json.Unmarshal(b, &mapping); err != nil {
		return err
	}
	if eq, ok := mapping[equalitySection]; ok {
		r.EqualityKey = eq["key"]
	}
	reNum := regexp.MustCompile(`\d+`)
	for cat, pairs := range mapping {
		if r.Categories[cat] == nil {
			continue
		}
		for original, replacement := range pairs {
			r.Categories[cat][original] = replacement
			counter := cat
			switch cat {
			case "fqdn", "hostlabel":
				counter = "hostname" // hostN, shared with short host names
			case "ip", "subnet_private", "subnet_public":
				continue // subnets are allocated around what is in use
			}
			if m := reNum.FindString(replacement); m != "" {
				if n, err := strconv.Atoi(m); err == nil && n > r.Counters[counter] {
					r.Counters[counter] = n
				}
			}
		}
	}
	return nil
}
