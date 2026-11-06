// Package verify checks obfuscated output for values that should not be
// there: originals from the mapping that were not replaced, and personal or
// network data the mapping could not know about (emails, public IPv4
// addresses, payment card numbers, LDAP names). Findings never print the
// value itself, so the report is safe to show to an agent.
package verify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/logline"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/redact"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/replace"
	"go.mongodb.org/mongo-driver/bson"
)

// Finding is one value that may be a leak.
type Finding struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"` // 0 for FTDC files
	// Path is the JSON/BSON key path, empty for plain text.
	Path string `json:"path,omitempty"`
	// Kind: mapped, email, public-ip, card-number, ldap, mapping-file.
	Kind string `json:"kind"`
	// Category of a mapped original (fqdn, database, ...).
	Category string `json:"category,omitempty"`
	// Hint identifies the value without revealing it: the replacement of a
	// mapped original, or a masked form ("j…(17 chars)").
	Hint string `json:"hint"`
}

type Report struct {
	Dir      string         `json:"dir"`
	Files    int            `json:"files"`
	Lines    int            `json:"lines"`
	Total    int            `json:"possibleLeaks"`
	Counts   map[string]int `json:"counts"`
	Samples  []Finding      `json:"samples"`
	Warnings []string       `json:"warnings,omitempty"`
}

type Options struct {
	// Mapping is the shared mapping (category -> original -> replacement).
	Mapping map[string]map[string]string
	// MappingPath is reported as a leak when it lies inside the directory.
	MappingPath string
	// MaxSamples bounds Report.Samples (one per distinct value); default 50.
	MaxSamples int
}

// Categories whose originals count as leaks when found in a key. Field names
// that equal a collection or database name are kept by design.
var keyCategories = map[string]bool{"hostname": true, "fqdn": true, "domain": true, "ip": true, "path": true, "email": true}

// Placeholder vocabulary: originals that occur inside it are not searched,
// or every replacement would match.
const vocabulary = "obfuscated string obfuscated payload obfuscated-number example.com /obfuscated/path database collection host domain user replset shard app data_ Organization Location com.example.app.Class redacted"

var (
	reEmail = regexp.MustCompile(`\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b`)
	reIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reCard  = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	reLDAP  = regexp.MustCompile(`(?i)\b(dc|cn|uid|o)=([^,;)\s"'\\{}*%?]+)`)
	// Replacement shapes the obfuscator writes into LDAP names.
	reReplacementName = regexp.MustCompile(`^((user|host|cert)\d+|Organization\d*$)`)
)

var commonDCs = map[string]bool{"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true, "int": true, "io": true, "local": true, "corp": true, "example": true, "internal": true, "lan": true}

// Extended JSON number and id wrappers hold digits that are not card numbers.
var numericWrapperKeys = map[string]bool{"$numberLong": true, "$numberInt": true, "$numberDouble": true, "$numberDecimal": true, "$date": true, "$oid": true, "$uuid": true, "base64": true, "t": true, "i": true}

type original struct {
	category, value, replacement string
	token                        bool
}

type checker struct {
	opts      Options
	originals []original
	ac        *matcher
	report    Report
	seen      map[string]bool
}

// Dir checks every file below dir.
func Dir(dir string, opts Options) (Report, error) {
	if opts.MaxSamples <= 0 {
		opts.MaxSamples = 50
	}
	c := &checker{opts: opts, seen: map[string]bool{}}
	c.report = Report{Dir: dir, Counts: map[string]int{}}
	var patterns []string
	cats := make([]string, 0, len(opts.Mapping))
	for cat := range opts.Mapping {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		for orig, repl := range opts.Mapping[cat] {
			if len(orig) < 3 || strings.Contains(vocabulary, orig) {
				continue
			}
			c.originals = append(c.originals, original{category: cat, value: orig, replacement: repl, token: replace.IdentifierLike(orig)})
			patterns = append(patterns, orig)
		}
	}
	c.ac = newMatcher(patterns)

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return c.report, err
	}
	mappingAbs := ""
	if opts.MappingPath != "" {
		mappingAbs, _ = filepath.Abs(opts.MappingPath)
	}
	err = filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(absDir, path)
		base := filepath.Base(path)
		if path == mappingAbs || base == "cluster_mapping.json" || strings.HasSuffix(base, "_mapping.json") {
			c.add(Finding{File: rel, Kind: "mapping-file", Hint: "a mapping file reverses the obfuscation; keep it outside the shared directory"})
			return nil
		}
		c.report.Files++
		if isFTDC(path) {
			return c.ftdcFile(path, rel)
		}
		return c.textFile(path, rel)
	})
	sort.SliceStable(c.report.Samples, func(i, j int) bool {
		a, b := c.report.Samples[i], c.report.Samples[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return c.report, err
}

func isFTDC(path string) bool {
	base := filepath.Base(path)
	if filepath.Base(filepath.Dir(path)) == "diagnostic.data" || strings.HasPrefix(base, "metrics.") || strings.HasSuffix(base, ".ftdc") {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 256)
	n, _ := f.Read(head)
	return bytes.IndexByte(head[:n], 0) >= 0
}

func (c *checker) textFile(path, rel string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	lineNo := 0
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			c.report.Lines++
			c.line(bytes.TrimRight(line, "\r\n"), rel, lineNo)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (c *checker) line(line []byte, rel string, lineNo int) {
	prefix, doc, structured := logline.Split(line)
	if structured {
		var v any
		if json.Unmarshal(doc, &v) == nil {
			if len(prefix) > 0 {
				c.check(string(prefix), "value", "", rel, lineNo, "")
			}
			c.walkJSON(v, nil, rel, lineNo)
			return
		}
	}
	c.check(string(line), "value", "", rel, lineNo, "")
}

func (c *checker) walkJSON(v any, path []string, rel string, lineNo int) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			p := append(path, k)
			c.check(k, "key", "", rel, lineNo, strings.Join(p, "."))
			c.walkJSON(val, p, rel, lineNo)
		}
	case []any:
		for _, item := range x {
			c.walkJSON(item, path, rel, lineNo)
		}
	case string:
		key := ""
		if len(path) > 0 {
			key = path[len(path)-1]
		}
		c.check(x, "value", key, rel, lineNo, strings.Join(path, "."))
	}
}

func (c *checker) ftdcFile(path, rel string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	docs, err := ftdc.Iterate(data)
	if err != nil {
		c.report.Warnings = append(c.report.Warnings, fmt.Sprintf("%s: %v", rel, err))
	}
	for _, raw := range docs {
		t, ok := ftdc.Type(raw.Doc)
		if !ok {
			continue
		}
		switch t {
		case ftdc.TypeMetadata, ftdc.TypePeriodicMetadata:
			if inner, ok := ftdc.DocField(raw.Doc, "doc"); ok {
				c.walkBSON(inner, nil, rel)
			}
		case ftdc.TypeMetricChunk:
			bin, ok := ftdc.BinaryField(raw.Doc, "data")
			if !ok {
				continue
			}
			chunk, err := ftdc.DecompressMetricChunk(bin.Data)
			if err != nil {
				c.report.Warnings = append(c.report.Warnings, fmt.Sprintf("%s: %v", rel, err))
				continue
			}
			var ref bson.D
			if err := bson.Unmarshal(chunk.RefBSON, &ref); err != nil {
				continue
			}
			c.walkBSON(ref, nil, rel)
		}
	}
	return nil
}

func (c *checker) walkBSON(v any, path []string, rel string) {
	switch x := v.(type) {
	case bson.D:
		for _, e := range x {
			p := append(path, e.Key)
			c.check(e.Key, "key", "", rel, 0, strings.Join(p, "."))
			c.walkBSON(e.Value, p, rel)
		}
	case bson.A:
		for _, item := range x {
			c.walkBSON(item, path, rel)
		}
	case string:
		key := ""
		if len(path) > 0 {
			key = path[len(path)-1]
		}
		c.check(x, "value", key, rel, 0, strings.Join(path, "."))
	}
}

// check looks for leaks in one key or string value.
func (c *checker) check(s, where, key, rel string, lineNo int, path string) {
	if s == "" {
		return
	}
	c.ac.each(s, func(id, start, end int) {
		o := c.originals[id]
		if o.token && !replace.TokenBoundary(s, start, end) {
			return
		}
		if where == "key" && !keyCategories[o.category] {
			return
		}
		c.add(Finding{File: rel, Line: lineNo, Path: path, Kind: "mapped", Category: o.category, Hint: "original of " + o.replacement})
	})
	if strings.IndexByte(s, '@') >= 0 {
		for _, m := range reEmail.FindAllString(s, -1) {
			domain := strings.ToLower(m[strings.LastIndexByte(m, '@')+1:])
			if domain == "example.com" || strings.HasSuffix(domain, ".example.com") {
				continue
			}
			c.add(Finding{File: rel, Line: lineNo, Path: path, Kind: "email", Hint: mask(m)})
		}
	}
	for _, m := range reIPv4.FindAllString(s, -1) {
		if publicIPv4(m) {
			c.add(Finding{File: rel, Line: lineNo, Path: path, Kind: "public-ip", Hint: mask(m)})
		}
	}
	if where == "value" && !numericWrapperKeys[key] {
		for _, m := range reCard.FindAllString(s, -1) {
			if redact.LuhnCard(m) {
				c.add(Finding{File: rel, Line: lineNo, Path: path, Kind: "card-number", Hint: mask(m)})
			}
		}
	}
	if strings.IndexByte(s, '=') >= 0 {
		for _, m := range reLDAP.FindAllStringSubmatch(s, -1) {
			attr, value := strings.ToLower(m[1]), m[2]
			if ((attr == "dc" || attr == "o") && commonDCs[strings.ToLower(value)]) || reReplacementName.MatchString(value) || len(value) < 2 {
				continue
			}
			c.add(Finding{File: rel, Line: lineNo, Path: path, Kind: "ldap", Hint: attr + "=" + mask(value)})
		}
	}
}

func (c *checker) add(f Finding) {
	label := f.Kind
	if f.Category != "" {
		label += " " + f.Category
	}
	c.report.Total++
	c.report.Counts[label]++
	id := label + "\x00" + f.Hint
	if c.seen[id] || len(c.report.Samples) >= c.opts.MaxSamples {
		return
	}
	c.seen[id] = true
	c.report.Samples = append(c.report.Samples, f)
}

func publicIPv4(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() {
		return false
	}
	b := ip.As4()
	switch {
	case ip.IsPrivate(), ip.IsLoopback(), ip.IsLinkLocalUnicast(), ip.IsMulticast(), ip.IsUnspecified():
		return false
	case b[0] == 0 || b[0] >= 240 || (b[0] == 100 && b[1]&0xc0 == 64): // reserved, CGNAT
		return false
	}
	return true
}

// mask keeps the first character and the length.
func mask(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return ""
	}
	return fmt.Sprintf("%c…(%d chars)", r[0], len(r))
}

// Write prints the report for a terminal.
func (r Report) Write(w io.Writer) {
	fmt.Fprintf(w, "Verify: %d file(s), %d text line(s) in %s\n", r.Files, r.Lines, r.Dir)
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  Warning: %s\n", warn)
	}
	if r.Total == 0 {
		fmt.Fprintln(w, "No possible leaks found.")
		return
	}
	fmt.Fprintf(w, "Possible leaks: %d\n", r.Total)
	labels := make([]string, 0, len(r.Counts))
	for l := range r.Counts {
		labels = append(labels, l)
	}
	sort.Slice(labels, func(i, j int) bool {
		if r.Counts[labels[i]] != r.Counts[labels[j]] {
			return r.Counts[labels[i]] > r.Counts[labels[j]]
		}
		return labels[i] < labels[j]
	})
	for _, l := range labels {
		fmt.Fprintf(w, "  %-22s %d\n", l, r.Counts[l])
	}
	fmt.Fprintln(w, "First occurrence of each value (values are masked):")
	for _, f := range r.Samples {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		kind := f.Kind
		if f.Category != "" {
			kind += " " + f.Category
		}
		path := ""
		if f.Path != "" {
			path = "  at " + f.Path
		}
		fmt.Fprintf(w, "  %s  %s: %s%s\n", loc, kind, f.Hint, path)
	}
}
