package processor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
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
	if summary.PayloadRedactions != 7 {
		t.Fatalf("PayloadRedactions = %d, want 7", summary.PayloadRedactions)
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
	if got := firstCommand["updates"].([]any); len(got) != 1 || got[0] != redact.Placeholder {
		t.Fatalf("updates not redacted: %#v", firstCommand["updates"])
	}
	if _, ok := firstCommand["update"].(string); !ok {
		t.Fatalf("command name update not preserved")
	}
	secondCommand := second["attr"].(map[string]any)["command"].(map[string]any)
	for _, key := range []string{"query", "update", "let"} {
		red, ok := secondCommand[key].(map[string]any)
		if !ok || red["redacted"] != redact.Placeholder {
			t.Fatalf("%s not redacted: %#v", key, secondCommand[key])
		}
	}
	truncated := third["attr"].(map[string]any)["truncated"].(map[string]any)["command"].(map[string]any)
	if got := truncated["documents"].([]any); len(got) != 1 || got[0] != redact.Placeholder {
		t.Fatalf("documents not redacted: %#v", truncated)
	}
	fourthCommand := fourth["attr"].(map[string]any)["command"].(map[string]any)
	for _, key := range []string{"q", "u"} {
		red, ok := fourthCommand[key].(map[string]any)
		if !ok || red["redacted"] != redact.Placeholder {
			t.Fatalf("%s not redacted: %#v", key, fourthCommand[key])
		}
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
	if summary.PayloadRedactions != 1 {
		t.Fatalf("PayloadRedactions = %d, want 1", summary.PayloadRedactions)
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
	if len(docsValue) != 1 || docsValue[0] != redact.Placeholder {
		t.Fatalf("documents not redacted: %#v", command)
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
	ref, err := bson.Marshal(bson.D{{Key: "command", Value: bson.D{{Key: "insert", Value: "notifications"}, {Key: "documents", Value: bson.A{bson.D{{Key: "emailBody", Value: "Card Ending 9999"}}}}, {Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}}}}, {Key: "opcounters", Value: bson.D{{Key: "insert", Value: int64(123)}}}})
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
