package registry

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strconv"
)

type Replacement struct {
	Original string
	Value    string
}

type Registry struct {
	Categories map[string]map[string]string
	Counters   map[string]int
}

type Collector struct {
	Values map[string]map[string]struct{}
}

var categories = []string{"hostname", "fqdn", "domain", "ip", "database", "collection", "replset", "shard", "user", "email", "path", "cert_subject", "org", "location", "java_class", "appname", "data"}

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

func (r *Registry) MergeCollectors(collectors []*Collector) {
	for _, c := range collectors {
		for _, cat := range categories {
			values := make([]string, 0, len(c.Values[cat]))
			for value := range c.Values[cat] {
				values = append(values, value)
			}
			sort.Strings(values)
			for _, value := range values {
				r.GetOrCreate(cat, value)
			}
		}
	}
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
	r.Counters[category]++
	replacement := template(category, r.Counters[category])
	r.Categories[category][original] = replacement
	return replacement
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
	var out []Replacement
	for _, cat := range cats {
		for original, replacement := range r.Categories[cat] {
			out = append(out, Replacement{Original: original, Value: replacement})
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
	reNum := regexp.MustCompile(`\d+`)
	for cat, pairs := range mapping {
		if r.Categories[cat] == nil {
			continue
		}
		for original, replacement := range pairs {
			r.Categories[cat][original] = replacement
			if m := reNum.FindString(replacement); m != "" {
				if n, err := strconv.Atoi(m); err == nil && n > r.Counters[cat] {
					r.Counters[cat] = n
				}
			}
		}
	}
	return nil
}
