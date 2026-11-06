package processor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/discover"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/logline"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/redact"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/replace"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Config struct {
	Files       []inputs.File
	InputRoot   string
	OutputRoot  string
	MappingPath string
	Jobs        int
	DryRun      bool
	Registry    *registry.Registry
}
type Summary struct {
	Files             int
	LogFiles          int
	FTDCFiles         int
	Replacements      int
	PayloadRedactions int
	DiscoverTime      time.Duration
	ReplaceTime       time.Duration
	// Outputs are the written paths, in the order of Config.Files.
	Outputs []string
}

// OutputPath is where the obfuscated copy of f is written: its path relative
// to the input root, below the output root, with mapped names (host names in
// file and directory names) replaced.
func OutputPath(f inputs.File, inputRoot, outputRoot string, names *replace.Matcher) string {
	rel := inputs.OutputRel(f.Path, inputRoot, f.Type)
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		parts[i] = names.ApplyName(part)
	}
	return filepath.Join(outputRoot, filepath.Join(parts...))
}

type fileResult struct {
	file   inputs.File
	result discover.Result
	err    error
}

func Run(cfg Config) (Summary, error) {
	if cfg.Registry == nil {
		cfg.Registry = registry.New()
	}
	if cfg.Jobs <= 0 {
		cfg.Jobs = 1
	}
	sort.Slice(cfg.Files, func(i, j int) bool { return cfg.Files[i].Path < cfg.Files[j].Path })
	summary := Summary{Files: len(cfg.Files)}
	for _, f := range cfg.Files {
		if f.Type == inputs.Log {
			summary.LogFiles++
		} else if f.Type == inputs.FTDC {
			summary.FTDCFiles++
		}
	}
	start := time.Now()
	results, err := discoverAll(cfg.Files, cfg.Jobs)
	summary.DiscoverTime = time.Since(start)
	if err != nil {
		return summary, err
	}
	collectors := make([]*registry.Collector, len(results))
	for i, r := range results {
		collectors[i] = r.result.Collector
		for _, w := range r.result.Warnings {
			fmt.Fprintf(os.Stderr, "  Warning: %s: %s\n", r.file.Path, w)
		}
	}
	cfg.Registry.MergeCollectors(collectors)
	reps := cfg.Registry.Replacements()
	summary.Replacements = len(reps)
	if cfg.DryRun {
		return summary, nil
	}
	if err := os.MkdirAll(cfg.OutputRoot, 0o755); err != nil {
		return summary, err
	}
	matcher := newObfuscator(cfg.Registry)
	names := replace.New(reps)
	outPaths := make([]string, len(cfg.Files))
	for i, f := range cfg.Files {
		outPaths[i] = OutputPath(f, cfg.InputRoot, cfg.OutputRoot, names)
	}
	summary.Outputs = outPaths
	start = time.Now()
	redactions, err := replaceAll(cfg.Files, outPaths, cfg.Jobs, matcher)
	if err != nil {
		return summary, err
	}
	summary.PayloadRedactions = redactions
	summary.ReplaceTime = time.Since(start)
	if err := os.MkdirAll(filepath.Dir(cfg.MappingPath), 0o755); err != nil {
		return summary, err
	}
	if err := cfg.Registry.Write(cfg.MappingPath); err != nil {
		return summary, err
	}
	return summary, nil
}

func discoverAll(files []inputs.File, jobs int) ([]fileResult, error) {
	type job struct {
		index int
		file  inputs.File
	}
	jobsCh := make(chan job)
	results := make([]fileResult, len(files))
	var wg sync.WaitGroup
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				var r discover.Result
				var err error
				if j.file.Type == inputs.Log {
					r, err = discover.LogFile(j.file.Path)
				} else {
					r, err = discover.FTDCFile(j.file.Path)
				}
				results[j.index] = fileResult{file: j.file, result: r, err: err}
			}
		}()
	}
	for i, file := range files {
		jobsCh <- job{index: i, file: file}
	}
	close(jobsCh)
	wg.Wait()
	for _, r := range results {
		if r.err != nil {
			return results, r.err
		}
	}
	return results, nil
}

func replaceAll(files []inputs.File, outPaths []string, jobs int, matcher *obfuscator) (int, error) {
	type job struct {
		file inputs.File
		out  string
	}
	type result struct {
		redactions int
		err        error
	}
	jobsCh := make(chan job)
	resultCh := make(chan result, len(files))
	var wg sync.WaitGroup
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				if err := os.MkdirAll(filepath.Dir(j.out), 0o755); err != nil {
					resultCh <- result{err: err}
					continue
				}
				var n int
				var err error
				if j.file.Type == inputs.Log {
					n, err = replaceLog(j.file.Path, j.out, matcher)
				} else {
					n, err = replaceFTDC(j.file.Path, j.out, matcher)
				}
				resultCh <- result{redactions: n, err: err}
			}
		}()
	}
	for i, f := range files {
		jobsCh <- job{file: f, out: outPaths[i]}
	}
	close(jobsCh)
	wg.Wait()
	close(resultCh)
	total := 0
	for r := range resultCh {
		total += r.redactions
		if r.err != nil {
			return total, r.err
		}
	}
	return total, nil
}

func replaceLog(inPath, outPath string, matcher *obfuscator) (int, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	r := bufio.NewReaderSize(in, 1024*1024)
	w := bufio.NewWriterSize(out, 1024*1024)
	defer w.Flush()
	total := 0
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			repl, n, e := matcher.logLine(line)
			if e != nil {
				return total, e
			}
			total += n
			if _, e := w.WriteString(repl); e != nil {
				return total, e
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func replaceFTDC(inPath, outPath string, matcher *obfuscator) (int, error) {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return 0, err
	}
	docs, err := ftdc.Iterate(data)
	if err != nil {
		return 0, err
	}
	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	w := bufio.NewWriterSize(out, 1024*1024)
	defer w.Flush()
	total := 0
	for _, raw := range docs {
		doc := raw.Doc
		t, ok := ftdc.Type(doc)
		if !ok {
			if _, err := w.Write(raw.Bytes); err != nil {
				return total, err
			}
			continue
		}
		switch t {
		case ftdc.TypeMetadata, ftdc.TypePeriodicMetadata:
			if inner, ok := ftdc.DocField(doc, "doc"); ok {
				ob, n := matcher.bsonDoc(inner, false)
				total += n
				doc = ftdc.ReplaceField(doc, "doc", ob)
			}
		case ftdc.TypeMetricChunk:
			if bin, ok := ftdc.BinaryField(doc, "data"); ok {
				chunk, err := ftdc.DecompressMetricChunk(bin.Data)
				if err == nil {
					var ref bson.D
					if err := bson.Unmarshal(chunk.RefBSON, &ref); err == nil {
						ob, n := matcher.bsonDoc(ref, false)
						total += n
						chunk.RefBSON, err = bson.Marshal(ob)
						if err != nil {
							return total, err
						}
						newChunk, err := ftdc.RecompressMetricChunk(chunk)
						if err != nil {
							return total, err
						}
						doc = ftdc.ReplaceField(doc, "data", primitive.Binary{Subtype: bin.Subtype, Data: newChunk})
					}
				}
			}
		}
		enc, err := bson.Marshal(doc)
		if err != nil {
			return total, err
		}
		if _, err := w.Write(enc); err != nil {
			return total, err
		}
	}
	return total, nil
}

// obfuscator applies the shared mapping: values to string values, keys to
// JSON/BSON keys (hosts, IPs and paths only), names to output file names.
type obfuscator struct {
	values *replace.Matcher
	keys   *replace.Matcher
}

func newObfuscator(reg *registry.Registry) *obfuscator {
	return &obfuscator{
		values: replace.New(reg.Replacements()),
		keys:   replace.New(reg.ReplacementsFor(registry.NetworkAndPathCategories...)),
	}
}

// text maps and scrubs free text: string values, log prefixes.
func (o *obfuscator) text(s string) (string, int) {
	return redact.ScrubText(o.values.Apply(s))
}

func (o *obfuscator) key(k string) string {
	if !strings.ContainsAny(k, ":/") {
		return k
	}
	return o.keys.Apply(k)
}

func replaceLogLine(line string, matcher *replace.Matcher) (string, int, error) {
	return (&obfuscator{values: matcher, keys: matcher}).logLine(line)
}

func (o *obfuscator) logLine(line string) (string, int, error) {
	newline := ""
	raw := line
	if strings.HasSuffix(raw, "\n") {
		newline = "\n"
		raw = strings.TrimSuffix(raw, "\n")
	}
	if strings.HasSuffix(raw, "\r") {
		newline = "\r" + newline
		raw = strings.TrimSuffix(raw, "\r")
	}
	prefix, doc, structured := logline.Split([]byte(raw))
	obj, err := parseOrderedJSON(doc)
	if err != nil || (!structured && len(prefix) > 0) {
		repl, n := o.text(line)
		redacted, m := redact.DirectText(repl)
		return redacted, n + m, nil
	}
	transformed, n := o.json(obj, "", false)
	enc, err := json.Marshal(transformed)
	if err != nil {
		return "", n, err
	}
	head, m := o.text(string(prefix))
	return head + string(enc) + newline, n + m, nil
}

type jsonObject []jsonMember

type jsonMember struct {
	key   string
	value any
}

func parseOrderedJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := parseJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	} else if err == nil {
		return nil, fmt.Errorf("unexpected trailing JSON")
	}
	return value, nil
}

func parseJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case json.Delim(123):
			var obj jsonObject
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("object key is %T", keyTok)
				}
				value, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				obj = append(obj, jsonMember{key: key, value: value})
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim(125) {
				return nil, fmt.Errorf("unexpected object terminator %v", end)
			}
			return obj, nil
		case json.Delim(91):
			var arr []any
			for dec.More() {
				value, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, value)
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim(93) {
				return nil, fmt.Errorf("unexpected array terminator %v", end)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", delim)
		}
	}
	return tok, nil
}

func (obj jsonObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(123)
	for i, member := range obj {
		if i > 0 {
			buf.WriteByte(44)
		}
		key, err := json.Marshal(member.key)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(member.value)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(58)
		buf.Write(value)
	}
	buf.WriteByte(125)
	return buf.Bytes(), nil
}

// json obfuscates a parsed log document. key is the key the value is stored
// under (the parent key for array items); inCommand is set below command
// objects, where only allowlisted strings are kept.
func (o *obfuscator) json(v any, key string, inCommand bool) (any, int) {
	switch x := v.(type) {
	case jsonObject:
		out := make(jsonObject, len(x))
		total := 0
		for i, member := range x {
			out[i].key = o.key(member.key)
			child := inCommand || redact.CommandContext(member.key)
			if child && member.key == "pipeline" {
				repl, n := o.pipelineJSON(member.value)
				out[i].value = repl
				total += n
				continue
			}
			if redact.DocumentContainer(member.key) || redact.PayloadField(member.key, member.value, child) {
				repl, n := redactJSONValue(member.value)
				out[i].value = repl
				total += n
				continue
			}
			repl, n := o.json(member.value, member.key, child)
			out[i].value = repl
			total += n
		}
		return out, total
	case []any:
		out := make([]any, len(x))
		total := 0
		for i, item := range x {
			repl, n := o.json(item, key, inCommand)
			out[i] = repl
			total += n
		}
		return out, total
	case string:
		if inCommand && !redact.CommandSafeString(key) {
			after := redact.Token(x)
			return after, countStringChange(x, after)
		}
		return o.text(x)
	default:
		return v, 0
	}
}

func redactJSONValue(value any) (any, int) {
	return redactJSONPayload(value, "")
}

func redactJSONPayload(value any, parentKey string) (any, int) {
	switch x := value.(type) {
	case jsonObject:
		out := make(jsonObject, len(x))
		total := 0
		for i, member := range x {
			out[i].key = member.key
			repl, n := redactJSONPayload(member.value, member.key)
			out[i].value = repl
			total += n
		}
		return out, total
	case []any:
		out := make([]any, len(x))
		total := 0
		for i, item := range x {
			repl, n := redactJSONPayload(item, parentKey)
			out[i] = repl
			total += n
		}
		return out, total
	case string:
		after := jsonStringPlaceholder(parentKey, x)
		return after, countStringChange(x, after)
	case json.Number:
		return json.Number("0"), countStringChange(x.String(), "0")
	case bool:
		if x {
			return false, 1
		}
		return false, 0
	case nil:
		return nil, 0
	default:
		return redact.StringPlaceholder, 1
	}
}

func jsonStringPlaceholder(parentKey, value string) string {
	switch parentKey {
	case "$date":
		return "1970-01-01T00:00:00Z"
	case "$oid":
		return "000000000000000000000000"
	case "$uuid":
		return "00000000-0000-0000-0000-000000000000"
	case "$numberLong", "$numberInt", "$numberDouble", "$numberDecimal":
		return "0"
	default:
		return redact.Token(value)
	}
}

func countStringChange(before, after string) int {
	if before == after {
		return 0
	}
	return 1
}

func obfuscateBSON(doc bson.D, matcher *replace.Matcher, inCommand bool) (bson.D, int) {
	return (&obfuscator{values: matcher, keys: matcher}).bsonDoc(doc, inCommand)
}

func (o *obfuscator) bsonDoc(doc bson.D, inCommand bool) (bson.D, int) {
	out := make(bson.D, len(doc))
	total := 0
	for i, elem := range doc {
		out[i].Key = o.key(elem.Key)
		child := inCommand || redact.CommandContext(elem.Key)
		if redact.DocumentContainer(elem.Key) || redact.PayloadField(elem.Key, elem.Value, child) {
			repl, n := redactBSONPayload(elem.Value, "")
			out[i].Value = repl
			total += n
			continue
		}
		repl, n := o.bsonValue(elem.Value, elem.Key, child)
		out[i].Value = repl
		total += n
	}
	return out, total
}

func (o *obfuscator) bsonValue(v any, key string, inCommand bool) (any, int) {
	switch x := v.(type) {
	case string:
		if inCommand && !redact.CommandSafeString(key) {
			after := redact.Token(x)
			return after, countStringChange(x, after)
		}
		return o.text(x)
	case bson.D:
		return o.bsonDoc(x, inCommand)
	case bson.A:
		out := make(bson.A, len(x))
		total := 0
		for i, item := range x {
			repl, n := o.bsonValue(item, key, inCommand)
			out[i] = repl
			total += n
		}
		return out, total
	default:
		return v, 0
	}
}

func redactBSONPayload(value any, parentKey string) (any, int) {
	switch x := value.(type) {
	case bson.D:
		out := make(bson.D, len(x))
		total := 0
		for i, elem := range x {
			out[i].Key = elem.Key
			repl, n := redactBSONPayload(elem.Value, elem.Key)
			out[i].Value = repl
			total += n
		}
		return out, total
	case bson.A:
		out := make(bson.A, len(x))
		total := 0
		for i, item := range x {
			repl, n := redactBSONPayload(item, parentKey)
			out[i] = repl
			total += n
		}
		return out, total
	case []any:
		out := make(bson.A, len(x))
		total := 0
		for i, item := range x {
			repl, n := redactBSONPayload(item, parentKey)
			out[i] = repl
			total += n
		}
		return out, total
	case string:
		after := jsonStringPlaceholder(parentKey, x)
		return after, countStringChange(x, after)
	case bool:
		if x {
			return false, 1
		}
		return false, 0
	case int:
		if x == 0 {
			return 0, 0
		}
		return 0, 1
	case int32:
		if x == 0 {
			return int32(0), 0
		}
		return int32(0), 1
	case int64:
		if x == 0 {
			return int64(0), 0
		}
		return int64(0), 1
	case float32:
		if x == 0 {
			return float32(0), 0
		}
		return float32(0), 1
	case float64:
		if x == 0 {
			return float64(0), 0
		}
		return float64(0), 1
	case primitive.DateTime:
		if x == 0 {
			return primitive.DateTime(0), 0
		}
		return primitive.DateTime(0), 1
	case primitive.ObjectID:
		zero := primitive.NilObjectID
		if x == zero {
			return zero, 0
		}
		return zero, 1
	case primitive.Timestamp:
		zero := primitive.Timestamp{}
		if x == zero {
			return zero, 0
		}
		return zero, 1
	case primitive.Decimal128:
		zero, _ := primitive.ParseDecimal128("0")
		if x == zero {
			return zero, 0
		}
		return zero, 1
	case primitive.Binary:
		zero := primitive.Binary{Subtype: x.Subtype, Data: make([]byte, len(x.Data))}
		if bytes.Equal(x.Data, zero.Data) {
			return zero, 0
		}
		return zero, 1
	case primitive.Regex:
		zero := primitive.Regex{Pattern: redact.StringPlaceholder}
		if x == zero {
			return zero, 0
		}
		return zero, 1
	case nil:
		return nil, 0
	default:
		return redact.StringPlaceholder, 1
	}
}
