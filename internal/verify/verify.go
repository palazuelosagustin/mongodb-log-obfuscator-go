// Package verify checks obfuscated output for values that should not be
// there: originals from the mapping that were not replaced, and personal or
// network data the mapping could not know about (emails, public IPv4
// addresses, payment card numbers, LDAP names). Findings never print the
// value itself, so the report is safe to show to an agent.
package verify

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/ahocorasick"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/logline"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/pipeline"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/redact"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/registry"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/replace"
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
	// Jobs is the number of workers (default 1).
	Jobs int
}

// Categories whose originals count as leaks when found in a key. Field names
// that equal a collection or database name are kept by design.
var keyCategories = map[string]bool{"hostname": true, "fqdn": true, "domain": true, "ip": true, "path": true, "email": true}

// Placeholder vocabulary: originals that occur inside it are not searched,
// or every replacement would match.
const vocabulary = "obf_ zone obfuscated string obfuscated payload obfuscated-number example.com /obfuscated/path database collection host domain user replset shard app data_ Organization Location com.example.app.Class redacted"

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
	ac        *ahocorasick.Matcher
	report    Report
	seen      map[string]bool
	mu        sync.Mutex // guards report and seen of the top checker
}

// fork returns a checker for one block or file that shares the patterns.
func (c *checker) fork() *checker {
	return &checker{opts: c.opts, originals: c.originals, ac: c.ac, seen: map[string]bool{}, report: Report{Counts: map[string]int{}}}
}

// merge adds the findings of a fork.
func (c *checker) merge(f *checker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.Total += f.report.Total
	c.report.Lines += f.report.Lines
	c.report.Files += f.report.Files
	for label, n := range f.report.Counts {
		c.report.Counts[label] += n
	}
	c.report.Warnings = append(c.report.Warnings, f.report.Warnings...)
	for _, s := range f.report.Samples {
		label := s.Kind
		if s.Category != "" {
			label += " " + s.Category
		}
		id := label + "\x00" + s.Hint
		if c.seen[id] || len(c.report.Samples) >= c.opts.MaxSamples {
			continue
		}
		c.seen[id] = true
		c.report.Samples = append(c.report.Samples, s)
	}
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
		if registry.Hidden(cat) || strings.HasPrefix(cat, "_") {
			continue // building blocks of host names and IPs, not values
		}
		for orig, repl := range opts.Mapping[cat] {
			if len(orig) < 3 || strings.Contains(vocabulary, orig) {
				continue
			}
			c.originals = append(c.originals, original{category: cat, value: orig, replacement: repl, token: replace.IdentifierLike(orig)})
			patterns = append(patterns, orig)
		}
	}
	c.ac = ahocorasick.New(patterns)

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return c.report, err
	}
	mappingAbs := ""
	if opts.MappingPath != "" {
		mappingAbs, _ = filepath.Abs(opts.MappingPath)
	}
	var paths []string
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
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return c.report, err
	}
	pool := pipeline.NewPool(opts.Jobs)
	defer pool.Close()
	files := make(chan string)
	errs := make(chan error, len(paths))
	var wg sync.WaitGroup
	for i := 0; i < pool.Size(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range files {
				rel, _ := filepath.Rel(absDir, path)
				var err error
				if isFTDC(path) {
					f := c.fork()
					pool.Do(func() { err = f.ftdcFile(path, rel) })
					f.report.Files = 1
					c.merge(f)
				} else {
					err = c.textFile(path, rel, pool)
				}
				if err != nil {
					errs <- fmt.Errorf("%s: %w", rel, err)
				}
			}
		}()
	}
	for _, p := range paths {
		files <- p
	}
	close(files)
	wg.Wait()
	close(errs)
	for e := range errs {
		if err == nil {
			err = e
		}
	}
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
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	return ftdc.Sniff(head[:n])
}

// textFile checks a text file in parallel blocks of lines.
func (c *checker) textFile(path, rel string, pool *pipeline.Pool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	var src io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer zr.Close()
		src = zr
	}
	c.merge(&checker{report: Report{Files: 1, Counts: map[string]int{}}})
	return pipeline.Lines(pool, src, func(block []byte, first int) (*checker, error) {
		f := c.fork()
		lineNo := first
		pipeline.EachLine(block, func(line []byte) error {
			f.report.Lines++
			f.line(bytes.TrimRight(line, "\r\n"), rel, lineNo)
			lineNo++
			return nil
		})
		return f, nil
	}, func(f *checker) error {
		c.merge(f)
		return nil
	})
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
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rd := ftdc.NewReader(bufio.NewReaderSize(f, 1<<20))
	for {
		raw, err := rd.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			c.report.Warnings = append(c.report.Warnings, fmt.Sprintf("%s: %v", rel, err))
			return nil
		}
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
	c.ac.Each(s, func(id, start, end int) {
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
	case b[0] == 0 || b[0] >= 240 || (b[0] == 100 && b[1]&0xc0 == 64) || (b[0] == 198 && b[1]&0xfe == 18): // reserved, CGNAT, benchmark range used for replacements
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
