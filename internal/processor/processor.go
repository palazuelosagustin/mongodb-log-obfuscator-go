package processor

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	// Outputs are the written paths.
	Outputs []string
	// Failures are files not written; Warnings are files written with a
	// problem (truncated FTDC, dropped documents).
	Failures []FileMessage
	Warnings []FileMessage
}

type FileMessage struct {
	Path    string
	Message string
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
	summary := Summary{}
	start := time.Now()
	results := discoverAll(cfg.Files, cfg.Jobs)
	summary.DiscoverTime = time.Since(start)
	var files []inputs.File
	var collectors []*registry.Collector
	for _, r := range results {
		for _, w := range r.result.Warnings {
			summary.Warnings = append(summary.Warnings, FileMessage{Path: r.file.Path, Message: w})
		}
		if r.err != nil {
			// A file that cannot be read is not written: its names were not
			// discovered, so its copy could not be obfuscated reliably.
			summary.Failures = append(summary.Failures, FileMessage{Path: r.file.Path, Message: r.err.Error()})
			continue
		}
		files = append(files, r.file)
		collectors = append(collectors, r.result.Collector)
	}
	for _, f := range files {
		if f.Type == inputs.Log {
			summary.LogFiles++
		} else if f.Type == inputs.FTDC {
			summary.FTDCFiles++
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
	outPaths := make([]string, len(files))
	for i, f := range files {
		outPaths[i] = OutputPath(f, cfg.InputRoot, cfg.OutputRoot, names)
	}
	start = time.Now()
	for _, r := range replaceAll(files, outPaths, cfg.Jobs, matcher) {
		summary.PayloadRedactions += r.redactions
		for _, w := range r.warnings {
			if !alreadyWarned(summary.Warnings, r.file.Path, w) {
				summary.Warnings = append(summary.Warnings, FileMessage{Path: r.file.Path, Message: w})
			}
		}
		if r.err != nil {
			summary.Failures = append(summary.Failures, FileMessage{Path: r.file.Path, Message: r.err.Error()})
			continue
		}
		summary.Files++
		summary.Outputs = append(summary.Outputs, r.out)
	}
	summary.ReplaceTime = time.Since(start)
	if err := os.MkdirAll(filepath.Dir(cfg.MappingPath), 0o755); err != nil {
		return summary, err
	}
	if err := cfg.Registry.Write(cfg.MappingPath); err != nil {
		return summary, err
	}
	return summary, nil
}

// alreadyWarned reports a warning of discovery that the write step repeats
// with more detail; the detailed one replaces it.
func alreadyWarned(warnings []FileMessage, path, msg string) bool {
	for i, w := range warnings {
		if w.Path == path && strings.HasPrefix(msg, w.Message) {
			warnings[i].Message = msg
			return true
		}
	}
	return false
}

func discoverAll(files []inputs.File, jobs int) []fileResult {
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
					r, err = discover.LogFile(j.file.Path, j.file.Gzip)
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
	return results
}

type replaceResult struct {
	file       inputs.File
	out        string
	redactions int
	warnings   []string
	err        error
}

// replaceAll writes every output; a file that fails has its partial output
// removed and does not stop the others.
func replaceAll(files []inputs.File, outPaths []string, jobs int, matcher *obfuscator) []replaceResult {
	jobsCh := make(chan int)
	results := make([]replaceResult, len(files))
	var wg sync.WaitGroup
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobsCh {
				f, out := files[idx], outPaths[idx]
				res := replaceResult{file: f, out: out}
				if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
					res.err = err
				} else if f.Type == inputs.Log {
					res.redactions, res.err = replaceLog(f.Path, out, f.Gzip, matcher)
				} else {
					res.redactions, res.warnings, res.err = replaceFTDC(f.Path, out, matcher)
				}
				if res.err != nil {
					os.Remove(out)
				}
				results[idx] = res
			}
		}()
	}
	for i := range files {
		jobsCh <- i
	}
	close(jobsCh)
	wg.Wait()
	return results
}

func replaceLog(inPath, outPath string, gz bool, matcher *obfuscator) (total int, err error) {
	in, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	var src io.Reader = in
	if gz {
		zr, err := gzip.NewReader(bufio.NewReaderSize(in, 1<<20))
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		src = zr
	}
	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	var dst io.Writer = out
	var zw *gzip.Writer
	if gz {
		zw, _ = gzip.NewWriterLevel(out, gzip.BestSpeed)
		dst = zw
	}
	r := bufio.NewReaderSize(src, 1<<20)
	w := bufio.NewWriterSize(dst, 1<<20)
	for {
		line, rerr := r.ReadString('\n')
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
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				return total, rerr
			}
			break
		}
	}
	if err := w.Flush(); err != nil {
		return total, err
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			return total, err
		}
	}
	return total, nil
}

// replaceFTDC streams an FTDC file document by document. Documents that
// cannot be decoded and obfuscated are dropped with a warning rather than
// copied: they may hold names. A file that ends inside a document (the
// metrics.interim of a running mongod) keeps its complete documents.
func replaceFTDC(inPath, outPath string, matcher *obfuscator) (total int, warnings []string, err error) {
	in, err := os.Open(inPath)
	if err != nil {
		return 0, nil, err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriterSize(out, 1<<20)
	rd := ftdc.NewReader(bufio.NewReaderSize(in, 1<<20))
	dropped := 0
	for {
		raw, rerr := rd.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			if errors.Is(rerr, ftdc.ErrTruncated) {
				warnings = append(warnings, rerr.Error()+"; the incomplete document is dropped")
				break
			}
			return total, warnings, rerr
		}
		doc, n, ok := obfuscateFTDCDocument(raw.Doc, matcher)
		total += n
		if !ok {
			dropped++
			continue
		}
		enc, err := bson.Marshal(doc)
		if err != nil {
			return total, warnings, err
		}
		if _, err := w.Write(enc); err != nil {
			return total, warnings, err
		}
	}
	if dropped > 0 {
		warnings = append(warnings, fmt.Sprintf("%d FTDC document(s) could not be decoded and were dropped", dropped))
	}
	return total, warnings, w.Flush()
}

// obfuscateFTDCDocument returns the obfuscated document, or ok=false when it
// cannot be decoded.
func obfuscateFTDCDocument(doc bson.D, matcher *obfuscator) (bson.D, int, bool) {
	t, ok := ftdc.Type(doc)
	if !ok {
		return nil, 0, false
	}
	switch t {
	case ftdc.TypeMetadata, ftdc.TypePeriodicMetadata:
		inner, ok := ftdc.DocField(doc, "doc")
		if !ok {
			return doc, 0, true
		}
		ob, n := matcher.bsonDoc(inner, false)
		return ftdc.ReplaceField(doc, "doc", ob), n, true
	case ftdc.TypeMetricChunk:
		bin, ok := ftdc.BinaryField(doc, "data")
		if !ok {
			return nil, 0, false
		}
		chunk, err := ftdc.DecompressMetricChunk(bin.Data)
		if err != nil {
			return nil, 0, false
		}
		var ref bson.D
		if err := bson.Unmarshal(chunk.RefBSON, &ref); err != nil {
			return nil, 0, false
		}
		ob, n := matcher.bsonDoc(ref, false)
		if chunk.RefBSON, err = bson.Marshal(ob); err != nil {
			return nil, 0, false
		}
		newChunk, err := ftdc.RecompressMetricChunk(chunk)
		if err != nil {
			return nil, 0, false
		}
		return ftdc.ReplaceField(doc, "data", primitive.Binary{Subtype: bin.Subtype, Data: newChunk}), n, true
	default:
		return nil, 0, false
	}
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
