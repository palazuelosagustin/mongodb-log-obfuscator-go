package processor

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/discover"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/redact"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/registry"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/replace"
)

// obfuscateLines runs discovery and replacement over lines, as Run does.
func obfuscateLines(t *testing.T, lines ...string) ([]string, *registry.Registry) {
	t.Helper()
	path := t.TempDir() + "/mongod.log"
	if err := writeFile(path, strings.Join(lines, "\n")+"\n"); err != nil {
		t.Fatal(err)
	}
	res, err := discover.LogFile(path, discover.LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	reg.MergeCollectors([]*registry.Collector{res.Collector})
	o := newObfuscator(reg)
	var out []string
	for _, line := range lines {
		repl, _, err := o.logLine(line + "\n")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.TrimSuffix(repl, "\n"))
	}
	return out, reg
}

func TestPipelinesKeepStructure(t *testing.T) {
	line := `{"t":{"$date":"2026-11-01T10:00:00Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"c","msg":"Slow query","attr":{"ns":"shop.orders","command":{"aggregate":"orders","pipeline":[{"$match":{"status":"SECRET1","total":{"$gt":500}}},{"$lookup":{"from":"customers","localField":"cid","foreignField":"_id","as":"c","pipeline":[{"$match":{"tier":"SECRET2"}}]}},{"$unwind":"$c"},{"$addFields":{"label":"SECRET3","n":{"$size":"$items"}}},{"$group":{"_id":"$c.region","sum":{"$sum":"$total"}}},{"$sort":{"sum":-1}},{"$limit":10},{"$merge":{"into":"report","whenMatched":"replace"}}],"cursor":{},"$db":"shop"},"durationMillis":300}}`
	out, reg := obfuscateLines(t, line)
	got := out[0]
	for _, secret := range []string{"SECRET", "customers", `"report"`, "shop"} {
		if strings.Contains(got, secret) {
			t.Errorf("%s remains: %s", secret, got)
		}
	}
	customers := reg.GetOrCreate("collection", "customers")
	report := reg.GetOrCreate("collection", "report")
	for _, want := range []string{`"from":"` + customers + `"`, `"localField":"cid"`, `"foreignField":"_id"`, `"as":"c"`, `{"$unwind":"$c"}`, `"$size":"$items"`, `"_id":"$c.region"`, `"$sum":"$total"`, `{"$sort":{"sum":-1}}`, `{"$limit":10}`, `"into":"` + report + `"`, `"whenMatched":"replace"`, `"total":{"$gt":0}`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if !json.Valid([]byte(got)) {
		t.Fatalf("invalid JSON: %s", got)
	}
}

func TestToolAndInternalNamesAreKept(t *testing.T) {
	lines := []string{
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"s":"I","c":"NETWORK","id":51800,"ctx":"c","msg":"client metadata","attr":{"remote":"10.1.2.3:4000","doc":{"application":{"name":"pbm-agent"}}}}`,
		`{"t":{"$date":"2026-11-01T10:00:01Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"c","msg":"Slow query","attr":{"ns":"admin.pbmBackups","appName":"pbm-agent","command":{"find":"pbmBackups","filter":{"status":"x"},"$db":"admin"},"durationMillis":300}}`,
		`{"t":{"$date":"2026-11-01T10:00:02Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"c","msg":"Slow query","attr":{"ns":"local.oplog.rs","command":{"find":"oplog.rs","$db":"local"},"durationMillis":300}}`,
		`{"t":{"$date":"2026-11-01T10:00:03Z"},"s":"E","c":"-","id":1,"ctx":"c","msg":"x","attr":{"error":"at java.util.concurrent.ThreadPoolExecutor.runWorker built on x86-64-01.build.eng.rdu2.redhat.com"}}`,
	}
	out, reg := obfuscateLines(t, lines...)
	text := strings.Join(out, "\n")
	for _, want := range []string{"pbm-agent", "admin.pbmBackups", `"find":"pbmBackups"`, "local.oplog.rs", "java.util.concurrent.ThreadPoolExecutor.runWorker"} {
		if !strings.Contains(text, want) {
			t.Errorf("lost %s:\n%s", want, text)
		}
	}
	if d := reg.Categories["domain"]; len(d) != 0 {
		t.Errorf("free text registered domains: %v", d)
	}
}

func TestKeepEqualityHashesEqualValuesEqually(t *testing.T) {
	redact.SetEqualityKey([]byte("test-key"))
	defer redact.SetEqualityKey(nil)
	m := replace.New(nil)
	a, _, _ := replaceLogLine(`{"t":{"$date":"2026-11-01T10:00:00Z"},"attr":{"command":{"find":"c","filter":{"k":"alice","j":"bob"}}}}`+"\n", m)
	b, _, _ := replaceLogLine(`{"t":{"$date":"2026-11-01T10:00:01Z"},"attr":{"command":{"find":"c","filter":{"k":"alice"}}}}`+"\n", m)
	tokenOf := func(line, key string) string {
		i := strings.Index(line, `"`+key+`":"`) + len(key) + 4
		return line[i : i+strings.Index(line[i:], `"`)]
	}
	if tokenOf(a, "k") != tokenOf(b, "k") || tokenOf(a, "k") == tokenOf(a, "j") || !strings.HasPrefix(tokenOf(a, "k"), "obf_") {
		t.Fatalf("hashes: %s / %s", a, b)
	}
	if strings.Contains(a+b, "alice") || strings.Contains(a, "bob") {
		t.Fatal("value kept")
	}
}

func writeFile(path, data string) error { return osWriteFile(path, []byte(data)) }

var osWriteFile = func(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }
