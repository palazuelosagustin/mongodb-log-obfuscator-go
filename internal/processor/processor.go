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
	matcher := replace.New(reps)
	start = time.Now()
	redactions, err := replaceAll(cfg.Files, cfg.InputRoot, cfg.OutputRoot, cfg.Jobs, matcher)
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

func replaceAll(files []inputs.File, inputRoot, outputRoot string, jobs int, matcher *replace.Matcher) (int, error) {
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
	for _, f := range files {
		jobsCh <- job{file: f, out: inputs.OutputPath(f.Path, inputRoot, outputRoot, f.Type)}
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

func replaceLog(inPath, outPath string, matcher *replace.Matcher) (int, error) {
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
			repl, n, e := replaceLogLine(line, matcher)
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

func replaceFTDC(inPath, outPath string, matcher *replace.Matcher) (int, error) {
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
				ob, n := obfuscateBSON(inner, matcher, false)
				total += n
				doc = ftdc.ReplaceField(doc, "doc", ob)
			}
		case ftdc.TypeMetricChunk:
			if bin, ok := ftdc.BinaryField(doc, "data"); ok {
				chunk, err := ftdc.DecompressMetricChunk(bin.Data)
				if err == nil {
					var ref bson.D
					if err := bson.Unmarshal(chunk.RefBSON, &ref); err == nil {
						ob, n := obfuscateBSON(ref, matcher, false)
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

func replaceLogLine(line string, matcher *replace.Matcher) (string, int, error) {
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
	obj, err := parseOrderedJSON([]byte(raw))
	if err != nil {
		repl := matcher.Apply(line)
		redacted, n := redact.DirectText(repl)
		return redacted, n, nil
	}
	transformed, n := obfuscateJSON(obj, matcher, false)
	enc, err := json.Marshal(transformed)
	if err != nil {
		return "", n, err
	}
	return string(enc) + newline, n, nil
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

func obfuscateJSON(v any, matcher *replace.Matcher, inCommand bool) (any, int) {
	switch x := v.(type) {
	case jsonObject:
		out := make(jsonObject, len(x))
		total := 0
		for i, member := range x {
			out[i].key = member.key
			child := inCommand || redact.CommandContext(member.key)
			if redact.PayloadField(member.key, member.value, child) {
				repl, n := redactJSONValue(member.value)
				out[i].value = repl
				total += n
				continue
			}
			repl, n := obfuscateJSON(member.value, matcher, child)
			out[i].value = repl
			total += n
		}
		return out, total
	case []any:
		out := make([]any, len(x))
		total := 0
		for i, item := range x {
			repl, n := obfuscateJSON(item, matcher, inCommand)
			out[i] = repl
			total += n
		}
		return out, total
	case string:
		return matcher.Apply(x), 0
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
		after := jsonStringPlaceholder(parentKey)
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

func jsonStringPlaceholder(parentKey string) string {
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
		return redact.StringPlaceholder
	}
}

func countStringChange(before, after string) int {
	if before == after {
		return 0
	}
	return 1
}

func obfuscateBSON(doc bson.D, matcher *replace.Matcher, inCommand bool) (bson.D, int) {
	out := make(bson.D, len(doc))
	total := 0
	for i, elem := range doc {
		out[i].Key = elem.Key
		child := inCommand || redact.CommandContext(elem.Key)
		if redact.PayloadField(elem.Key, elem.Value, child) {
			repl, n := redactBSONPayload(elem.Value, "")
			out[i].Value = repl
			total += n
			continue
		}
		repl, n := obfuscateValue(elem.Value, matcher, child)
		out[i].Value = repl
		total += n
	}
	return out, total
}

func obfuscateValue(v any, matcher *replace.Matcher, inCommand bool) (any, int) {
	switch x := v.(type) {
	case string:
		return matcher.Apply(x), 0
	case bson.D:
		return obfuscateBSON(x, matcher, inCommand)
	case bson.A:
		out := make(bson.A, len(x))
		total := 0
		for i, item := range x {
			repl, n := obfuscateValue(item, matcher, inCommand)
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
		after := jsonStringPlaceholder(parentKey)
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
