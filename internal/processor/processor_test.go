package processor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/redact"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/replace"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestRunObfuscatesLogsAndFTDC(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "mongod.log")
	logLine := `{"msg":"client alice@example.com connected from app1.prod.example.com:27017","attr":{"hostAndPort":"app1.prod.example.com:27017","ns":"customer.orders","user":"alice@example.com","path":"/var/lib/mongo"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(logLine), 0o644); err != nil {
		t.Fatal(err)
	}
	ftdcPath := filepath.Join(root, "diagnostic.data", "metrics.1")
	if err := os.MkdirAll(filepath.Dir(ftdcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	delta := []byte{9, 8, 7, 6}
	if err := os.WriteFile(ftdcPath, buildFTDC(t, delta), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	summary, err := Run(Config{Files: []inputs.File{{Path: ftdcPath, Type: inputs.FTDC}, {Path: logPath, Type: inputs.Log}}, InputRoot: root, OutputRoot: out, MappingPath: filepath.Join(out, "cluster_mapping.json"), Jobs: 2, Registry: registry.New()})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Replacements == 0 {
		t.Fatal("expected replacements")
	}
	obfuscatedLog, err := os.ReadFile(filepath.Join(out, "mongod_obfuscated.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(obfuscatedLog), "prod.example.com") || strings.Contains(string(obfuscatedLog), "customer.orders") || strings.Contains(string(obfuscatedLog), "alice@example.com") {
		t.Fatalf("sensitive values remain in log: %s", obfuscatedLog)
	}
	outFTDC, err := os.ReadFile(filepath.Join(out, "diagnostic.data", "metrics.1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(outFTDC, []byte("app1.prod.example.com")) || bytes.Contains(outFTDC, []byte("orders")) {
		t.Fatalf("sensitive values remain in FTDC")
	}
	docs, err := ftdc.Iterate(outFTDC)
	if err != nil {
		t.Fatal(err)
	}
	bin, ok := ftdc.BinaryField(docs[1].Doc, "data")
	if !ok {
		t.Fatal("missing metric chunk data")
	}
	chunk, err := ftdc.DecompressMetricChunk(bin.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chunk.DeltaStream, delta) {
		t.Fatalf("delta stream changed: %v", chunk.DeltaStream)
	}
}

func TestRunRedactsJSONCommandPayloadsWithoutMapping(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "mongod.log")
	records := []string{`{"t":{"$date":"2026-07-23T00:00:00Z"},"s":"I","c":"COMMAND","msg":"Slow query","attr":{"ns":"payments.notifications","remote":"203.0.113.15:43210","planSummary":"IXSCAN { userId: 1 }","docsExamined":12,"keysExamined":2,"durationMillis":99,"command":{"update":"notifications","updates":[{"q":{"phone":"+966555111222"},"u":{"$set":{"emailBody":"Credit card XX Card Ending 9876 Amount: SAR 25 Remaining limit","smsBody":"تم استخدام البطاقة المنتهية 9876","merchant":"Riyadh Merchant LLC"}}}],"writeConcern":{"w":"majority"}}}}`, `{"t":{"$date":"2026-07-23T00:00:01Z"},"s":"I","c":"COMMAND","msg":"Slow query","attr":{"ns":"payments.notifications","command":{"findAndModify":"notifications","query":{"cardEnding":"1234","merchant":"Jeddah Shop"},"update":{"$set":{"template":{"content":"Card Ending 1234"}}},"let":{"channelOptions":{"emailBodyText":"Amount: SAR 125"}}}}}`, `{"t":{"$date":"2026-07-23T00:00:02Z"},"s":"I","c":"COMMAND","msg":"Slow query","attr":{"truncated":{"command":{"insert":"notifications","documents":[{"body":"Card Ending 4321","phoneNumber":"+966555333444"}]}}}}`, `{"t":{"$date":"2026-07-23T00:00:03Z"},"s":"I","c":"WRITE","msg":"Slow query","attr":{"ns":"payments.devices","command":{"q":{"device_id":"payload-device","seed":"payload-seed","user_id":"payload-user"},"u":{"$set":{"last_authenticated_at":1782807063397,"seed":"payload-updated-seed"}},"multi":true,"upsert":false},"docsExamined":1,"keysExamined":1,"durationMillis":735,"planSummary":"IXSCAN { device_id: 1, user_id: 1, seed: 1 }"}}`}
	if err := os.WriteFile(logPath, []byte(strings.Join(records, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	summary, err := Run(Config{Files: []inputs.File{{Path: logPath, Type: inputs.Log}}, InputRoot: root, OutputRoot: out, MappingPath: filepath.Join(out, "cluster_mapping.json"), Jobs: 1, Registry: registry.New()})
	if err != nil {
		t.Fatal(err)
	}
	if summary.PayloadRedactions != 15 {
		t.Fatalf("PayloadRedactions = %d, want 15", summary.PayloadRedactions)
	}
	obfuscatedLog, err := os.ReadFile(filepath.Join(out, "mongod_obfuscated.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(obfuscatedLog)), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %d, want 4", len(lines))
	}
	var first, second, third, fourth map[string]any
	for i, target := range []*map[string]any{&first, &second, &third, &fourth} {
		if err := json.Unmarshal([]byte(lines[i]), target); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i+1, err)
		}
	}
	firstAttr := first["attr"].(map[string]any)
	firstCommand := firstAttr["command"].(map[string]any)
	updates := firstCommand["updates"].([]any)
	if len(updates) != 1 {
		t.Fatalf("updates length = %d, want 1", len(updates))
	}
	firstUpdate := updates[0].(map[string]any)
	firstQ := firstUpdate["q"].(map[string]any)
	if firstQ["phone"] != redact.StringPlaceholder {
		t.Fatalf("query shape not preserved/redacted: %#v", firstQ)
	}
	firstSet := firstUpdate["u"].(map[string]any)["$set"].(map[string]any)
	for _, key := range []string{"emailBody", "smsBody", "merchant"} {
		if firstSet[key] != redact.StringPlaceholder {
			t.Fatalf("update field %s not scalar-redacted: %#v", key, firstSet)
		}
	}
	if _, ok := firstCommand["update"].(string); !ok {
		t.Fatalf("command name update not preserved")
	}
	secondCommand := second["attr"].(map[string]any)["command"].(map[string]any)
	secondQuery := secondCommand["query"].(map[string]any)
	if secondQuery["cardEnding"] != redact.StringPlaceholder || secondQuery["merchant"] != redact.StringPlaceholder {
		t.Fatalf("query fields not preserved/redacted: %#v", secondQuery)
	}
	secondUpdate := secondCommand["update"].(map[string]any)["$set"].(map[string]any)["template"].(map[string]any)
	if secondUpdate["content"] != redact.StringPlaceholder {
		t.Fatalf("nested update not preserved/redacted: %#v", secondCommand["update"])
	}
	secondLet := secondCommand["let"].(map[string]any)["channelOptions"].(map[string]any)
	if secondLet["emailBodyText"] != redact.StringPlaceholder {
		t.Fatalf("let not preserved/redacted: %#v", secondCommand["let"])
	}
	truncated := third["attr"].(map[string]any)["truncated"].(map[string]any)["command"].(map[string]any)
	documents := truncated["documents"].([]any)
	if len(documents) != 1 {
		t.Fatalf("documents length = %d, want 1", len(documents))
	}
	doc := documents[0].(map[string]any)
	if doc["body"] != redact.StringPlaceholder || doc["phoneNumber"] != redact.StringPlaceholder {
		t.Fatalf("documents not scalar-redacted: %#v", documents)
	}
	fourthCommand := fourth["attr"].(map[string]any)["command"].(map[string]any)
	fourthQ := fourthCommand["q"].(map[string]any)
	for _, key := range []string{"device_id", "seed", "user_id"} {
		if fourthQ[key] != redact.StringPlaceholder {
			t.Fatalf("q field %s not scalar-redacted: %#v", key, fourthQ)
		}
	}
	fourthSet := fourthCommand["u"].(map[string]any)["$set"].(map[string]any)
	if fourthSet["last_authenticated_at"] != float64(0) || fourthSet["seed"] != redact.StringPlaceholder {
		t.Fatalf("u fields not type-redacted: %#v", fourthSet)
	}
	mapping, err := os.ReadFile(filepath.Join(out, "cluster_mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"Card Ending", "Credit card XX", "Riyadh Merchant", "Jeddah Shop", "Amount: SAR", "Remaining limit", "تم استخدام", "+966555", "payload-device", "payload-seed", "payload-user", "payload-updated-seed"} {
		if strings.Contains(string(obfuscatedLog), needle) {
			t.Fatalf("payload %q remains in log", needle)
		}
		if strings.Contains(string(mapping), needle) {
			t.Fatalf("payload %q was written to mapping", needle)
		}
	}
}

func TestObfuscatedSlowQueryWorksWithMongoDBLogstatQueryReport(t *testing.T) {
	logstatPath, err := exec.LookPath("mongodb-logstat")
	if err != nil {
		t.Skipf("mongodb-logstat not available: %v", err)
	}
	root := t.TempDir()
	logPath := filepath.Join(root, "mongod.log")
	line := `{"t":{"$date":"2026-06-30T12:00:00.017Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"conn42","msg":"Slow query","attr":{"type":"command","ns":"payments.cronLock","command":{"find":"cronLock","filter":{"key":"fallback_cron_lock","lastRun":{"$lt":{"$date":"2026-06-30T07:59:57Z"}}},"limit":1,"singleBatch":true},"planSummary":"IXSCAN { key: 1, lastRun: 1 }","keysExamined":2,"docsExamined":1,"nreturned":1,"durationMillis":12}}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	if _, err := Run(Config{Files: []inputs.File{{Path: logPath, Type: inputs.Log}}, InputRoot: root, OutputRoot: out, MappingPath: filepath.Join(out, "cluster_mapping.json"), Jobs: 1, Registry: registry.New()}); err != nil {
		t.Fatal(err)
	}
	obfuscatedPath := filepath.Join(out, "mongod_obfuscated.log")
	obfuscated, err := os.ReadFile(obfuscatedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"key", "lastRun", "$lt"} {
		if !bytes.Contains(obfuscated, []byte(needle)) {
			t.Fatalf("obfuscated log missing %q: %s", needle, obfuscated)
		}
	}
	output, err := exec.Command(logstatPath, "--report", "queries", "--json", obfuscatedPath).CombinedOutput()
	if err != nil {
		t.Fatalf("mongodb-logstat failed: %v\n%s", err, output)
	}
	var report map[string]any
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("invalid mongodb-logstat JSON: %v\n%s", err, output)
	}
	diagnostics := report["diagnostics"].(map[string]any)
	if diagnostics["acceptedSlowOperations"] != float64(1) {
		t.Fatalf("acceptedSlowOperations = %#v, report: %s", diagnostics["acceptedSlowOperations"], output)
	}
	rows := report["rows"].([]any)
	if len(rows) == 0 {
		t.Fatalf("expected at least one query row: %s", output)
	}
}

func TestReplaceLogLinePreservesMongoLogFieldOrder(t *testing.T) {
	line := `{"t":{"date":"2026-06-30T12:00:00.017+04:00"},"s":"W",  "c":"COMMAND",  "id":23802,   "ctx":"conn485182","msg":"Plan executor error during findAndModify","attr":{"error":{"code":11000,"codeName":"DuplicateKey"},"stats":{"stage":"UPDATE","nReturned":0,"executionTimeMillisEstimate":0},"cmd":{"findAndModify":"cronLock","query":{"key":"fallback_cron_lock"},"remove":false,"update":{"set":{"lastRun":{"date":"2026-06-30T08:00:00.012Z"}}},"upsert":true,"new":false}}}` + "\n"
	repl, _, err := replaceLogLine(line, replace.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	assertKeyOrder(t, repl, "\"t\"", "\"s\"", "\"c\"", "\"id\"", "\"ctx\"", "\"msg\"", "\"attr\"")
	assertKeyOrder(t, repl, "\"error\"", "\"stats\"", "\"cmd\"")
	assertKeyOrder(t, repl, "\"stage\"", "\"nReturned\"", "\"executionTimeMillisEstimate\"")
}

func assertKeyOrder(t *testing.T, text string, keys ...string) {
	t.Helper()
	last := -1
	for _, key := range keys {
		idx := strings.Index(text, key)
		if idx < 0 {
			t.Fatalf("missing key %s in %s", key, text)
		}
		if idx <= last {
			t.Fatalf("key %s is out of order in %s", key, text)
		}
		last = idx
	}
}

func TestReplaceLogLineDirectPayloadFallback(t *testing.T) {
	line := `command: { documents: [{ emailBody: "Card Ending 5555" }], phoneNumber: "+966555999888" }` + "\n"
	redacted, count, err := replaceLogLine(line, replace.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected fallback redactions")
	}
	if !strings.Contains(redacted, redact.Placeholder) || strings.Contains(redacted, "Card Ending") || strings.Contains(redacted, "+966555999888") {
		t.Fatalf("fallback redaction failed: %s", redacted)
	}
}

func TestRunRedactsFTDCPayloadsAndPreservesDeltaStream(t *testing.T) {
	root := t.TempDir()
	ftdcPath := filepath.Join(root, "diagnostic.data", "metrics.2")
	if err := os.MkdirAll(filepath.Dir(ftdcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	delta := []byte{1, 2, 3, 4, 5, 6}
	if err := os.WriteFile(ftdcPath, buildPayloadFTDC(t, delta), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	summary, err := Run(Config{Files: []inputs.File{{Path: ftdcPath, Type: inputs.FTDC}}, InputRoot: root, OutputRoot: out, MappingPath: filepath.Join(out, "cluster_mapping.json"), Jobs: 1, Registry: registry.New()})
	if err != nil {
		t.Fatal(err)
	}
	if summary.PayloadRedactions != 4 {
		t.Fatalf("PayloadRedactions = %d, want 4", summary.PayloadRedactions)
	}
	outFTDC, err := os.ReadFile(filepath.Join(out, "diagnostic.data", "metrics.2"))
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ftdc.Iterate(outFTDC)
	if err != nil {
		t.Fatal(err)
	}
	bin, ok := ftdc.BinaryField(docs[0].Doc, "data")
	if !ok {
		t.Fatal("missing data")
	}
	chunk, err := ftdc.DecompressMetricChunk(bin.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chunk.DeltaStream, delta) {
		t.Fatalf("delta changed")
	}
	var ref bson.D
	if err := bson.Unmarshal(chunk.RefBSON, &ref); err != nil {
		t.Fatal(err)
	}
	command, _ := bsonDocField(ref, "command")
	docsValue, _ := bsonArrayField(command, "documents")
	if len(docsValue) != 2 {
		t.Fatalf("documents length = %d, want 2: %#v", len(docsValue), command)
	}
	firstDoc, ok := docsValue[0].(bson.D)
	if !ok {
		t.Fatalf("first document is %T", docsValue[0])
	}
	if bsonStringValue(firstDoc, "emailBody") != redact.StringPlaceholder || bsonInt64Value(firstDoc, "amount") != 0 || bsonBoolValue(firstDoc, "sent") {
		t.Fatalf("first document not type-redacted: %#v", firstDoc)
	}
	secondDoc, ok := docsValue[1].(bson.D)
	if !ok {
		t.Fatalf("second document is %T", docsValue[1])
	}
	if bsonStringValue(secondDoc, "phoneNumber") != redact.StringPlaceholder {
		t.Fatalf("second document not redacted: %#v", secondDoc)
	}
	wc, _ := bsonDocField(command, "writeConcern")
	if bsonStringValue(wc, "w") != "majority" {
		t.Fatalf("writeConcern changed: %#v", command)
	}
	counters, _ := bsonDocField(ref, "opcounters")
	if bsonInt64Value(counters, "insert") != 123 {
		t.Fatalf("numeric metric changed: %#v", ref)
	}
}

func buildFTDC(t *testing.T, delta []byte) []byte {
	t.Helper()
	metadata, err := bson.Marshal(bson.D{{Key: "type", Value: int32(ftdc.TypeMetadata)}, {Key: "doc", Value: bson.D{{Key: "hostAndPort", Value: "app1.prod.example.com:27017"}, {Key: "set", Value: "rs-prod"}, {Key: "members", Value: bson.A{bson.D{{Key: "name", Value: "app2.prod.example.com:27017"}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := bson.Marshal(bson.D{{Key: "serverStatus", Value: bson.D{{Key: "host", Value: "app1.prod.example.com"}, {Key: "ns", Value: "customer.orders"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var counts [8]byte
	binary.LittleEndian.PutUint32(counts[:4], 2)
	binary.LittleEndian.PutUint32(counts[4:], 3)
	chunkBytes, err := ftdc.RecompressMetricChunk(ftdc.MetricChunk{RefBSON: ref, MetricsCount: binary.LittleEndian.Uint32(counts[:4]), DeltaCount: binary.LittleEndian.Uint32(counts[4:]), DeltaStream: delta})
	if err != nil {
		t.Fatal(err)
	}
	chunkDoc, err := bson.Marshal(bson.D{{Key: "type", Value: int32(ftdc.TypeMetricChunk)}, {Key: "data", Value: primitive.Binary{Subtype: 0, Data: chunkBytes}}})
	if err != nil {
		t.Fatal(err)
	}
	return append(metadata, chunkDoc...)
}
func buildPayloadFTDC(t *testing.T, delta []byte) []byte {
	t.Helper()
	ref, err := bson.Marshal(bson.D{{Key: "command", Value: bson.D{{Key: "insert", Value: "notifications"}, {Key: "documents", Value: bson.A{bson.D{{Key: "emailBody", Value: "Card Ending 9999"}, {Key: "amount", Value: int32(25)}, {Key: "sent", Value: true}}, bson.D{{Key: "phoneNumber", Value: "+966555333444"}}}}, {Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}}}}, {Key: "opcounters", Value: bson.D{{Key: "insert", Value: int64(123)}}}})
	if err != nil {
		t.Fatal(err)
	}
	chunkBytes, err := ftdc.RecompressMetricChunk(ftdc.MetricChunk{RefBSON: ref, MetricsCount: 3, DeltaCount: 2, DeltaStream: delta})
	if err != nil {
		t.Fatal(err)
	}
	chunkDoc, err := bson.Marshal(bson.D{{Key: "type", Value: int32(ftdc.TypeMetricChunk)}, {Key: "data", Value: primitive.Binary{Subtype: 0, Data: chunkBytes}}})
	if err != nil {
		t.Fatal(err)
	}
	return chunkDoc
}
func bsonDocField(doc bson.D, key string) (bson.D, bool) {
	for _, e := range doc {
		if e.Key == key {
			v, ok := e.Value.(bson.D)
			return v, ok
		}
	}
	return nil, false
}
func bsonArrayField(doc bson.D, key string) (bson.A, bool) {
	for _, e := range doc {
		if e.Key == key {
			v, ok := e.Value.(bson.A)
			return v, ok
		}
	}
	return nil, false
}
func bsonStringValue(doc bson.D, key string) string {
	for _, e := range doc {
		if e.Key == key {
			v, _ := e.Value.(string)
			return v
		}
	}
	return ""
}
func bsonBoolValue(doc bson.D, key string) bool {
	for _, e := range doc {
		if e.Key == key {
			v, _ := e.Value.(bool)
			return v
		}
	}
	return false
}

func bsonInt64Value(doc bson.D, key string) int64 {
	for _, e := range doc {
		if e.Key == key {
			switch v := e.Value.(type) {
			case int64:
				return v
			case int32:
				return int64(v)
			case int:
				return int64(v)
			}
		}
	}
	return 0
}
