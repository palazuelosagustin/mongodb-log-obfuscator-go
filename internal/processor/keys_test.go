package processor

import (
	"strings"
	"testing"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/verify"
)

// Names used as keys: an application document describing the catalog, a
// namespace key, and a path key that ends in a user name (/run/user/<uid>).
func TestNamesInKeysAreMapped(t *testing.T) {
	lines := []string{
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"s":"I","c":"ACCESS","id":20250,"ctx":"c","msg":"Authentication succeeded","attr":{"mechanism":"SCRAM-SHA-256","principalName":"1000123456","authenticationDatabase":"admin","remote":"10.1.2.3:4000"}}`,
		`{"t":{"$date":"2026-11-01T10:00:01Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"c","msg":"Slow query","attr":{"type":"update","ns":"shop.catalogs","command":{"update":"catalogs","updates":[{"q":{"_id":1},"u":{"$set":{"data":{"catalog":{"shop":{"collections":{"orders":{"uuid":{"$uuid":"3169e03a-f3e2-4119-9a6b-fcb879416c81"}}}},"shop.orders":{"count":1}}}}}}],"$db":"shop"},"durationMillis":150}}`,
		`{"t":{"$date":"2026-11-01T10:00:02Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"c","msg":"Slow query","attr":{"ns":"shop.orders","command":{"find":"orders","filter":{"orders":"x"},"$db":"shop"},"durationMillis":150}}`,
		`{"t":{"$date":"2026-11-01T10:00:03Z"},"s":"I","c":"-","id":1,"ctx":"c","msg":"x","attr":{"mounts":{"/run/user/1000123456":{"capacity":1}}}}`,
	}
	out, reg := obfuscateLines(t, lines...)
	text := strings.Join(out, "\n")
	for _, leak := range []string{`"shop"`, `"shop.orders"`, `"orders":{"uuid"`, "1000123456"} {
		if strings.Contains(text, leak) {
			t.Errorf("%s remains:\n%s", leak, text)
		}
	}
	db := reg.Categories["database"]["shop"]
	coll := reg.Categories["collection"]["orders"]
	user := reg.Categories["user"]["1000123456"]
	if db == "" || coll == "" || user == "" {
		t.Fatalf("names not registered: db=%q coll=%q user=%q", db, coll, user)
	}
	for _, want := range []string{
		`"catalog":{"` + db + `":{"collections":{"` + coll + `":{"uuid"`, // same names as in ns
		`"` + db + `.` + coll + `":{"count":0}`,
		`"/run/user/` + user + `":{"capacity":1}`, // the path stays readable
		`"filter":{"orders":`,                     // a field name that equals a collection stays
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s:\n%s", want, text)
		}
	}
}

// MongoDB's own query hashes identify lines across logs, explain output and
// the plan cache, so they keep their original values.
func TestQueryHashesAreKept(t *testing.T) {
	hashes := []string{`"queryHash":"B432B90C"`, `"planCacheKey":"7A8B9C0D"`, `"planCacheShapeHash":"5F1A2B3C"`, `"queryShapeHash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"`}
	line := `{"t":{"$date":"2026-11-01T10:00:00Z"},"s":"I","c":"COMMAND","id":51803,"ctx":"c","msg":"Slow query","attr":{"type":"command","ns":"shop.orders","command":{"find":"orders","filter":{"status":"paid"},"$db":"shop"},"planSummary":"COLLSCAN",` + strings.Join(hashes, ",") + `,"durationMillis":150}}`
	out, _ := obfuscateLines(t, line)
	for _, h := range hashes {
		if !strings.Contains(out[0], h) {
			t.Errorf("lost %s:\n%s", h, out[0])
		}
	}
}

func TestVerifyFindsNamesInKeys(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"u":{"catalog":{"shop":{"collections":{"orders":{}}}}}}}`, // db key + collection under collections
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"u":{"catalog":{"database1":{"collections":{"orders":{}}}}}}}`,
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"stats":{"shop.orders":{}}}}`,         // namespace key
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"mounts":{"/run/user/jdoe":{}}}}`,     // user in a path key
		`{"t":{"$date":"2026-11-01T10:00:00Z"},"msg":"x","attr":{"filter":{"orders":"x","jdoe":"y"}}}`, // field names: kept by design
	}
	if err := writeFile(dir+"/mongod_obfuscated.log", strings.Join(lines, "\n")+"\n"); err != nil {
		t.Fatal(err)
	}
	mapping := map[string]map[string]string{
		"database":   {"shop": "database1"},
		"collection": {"orders": "collection1"},
		"user":       {"jdoe": "user1"},
	}
	report, err := verify.Dir(dir, verify.Options{Mapping: mapping})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"mapped database": 2, "mapped collection": 2, "mapped user": 1}
	for label, n := range want {
		if report.Counts[label] != n {
			t.Errorf("%s = %d, want %d (counts %v)", label, report.Counts[label], n, report.Counts)
		}
	}
	var b strings.Builder
	report.Write(&b)
	for _, secret := range []string{"shop", "orders", "jdoe"} {
		if strings.Contains(b.String(), secret) {
			t.Errorf("report prints %q:\n%s", secret, b.String())
		}
	}
}
