package processor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/registry"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/verify"
)

// Lines modelled on leaks found in case logs; every sensitive value starts
// with "SECRET" or is a name listed in secrets.
var leakLines = []string{
	// replicated operation: the whole document is logged
	`{"t":{"$date":"2026-11-01T10:00:00.000Z"},"s":"I","c":"REPL","id":51801,"ctx":"ReplWriterWorker-1","msg":"Applied op","attr":{"CRUD":{"op":"u","ns":"bank.accounts","o":{"$v":2,"diff":{"u":{"firstName":"SECRETLaura","balance":1619.23}}},"o2":{"_id":"SECRET119187231"}},"durationMillis":0}}`,
	// 6.0 authentication field names
	`{"t":{"$date":"2026-11-01T10:00:01.000Z"},"s":"I","c":"ACCESS","id":20250,"ctx":"conn1","msg":"Authentication succeeded","attr":{"mechanism":"SCRAM-SHA-256","principalName":"SECRETjdoe","authenticationDatabase":"bank","remote":"203.0.113.7:51234"}}`,
	// free-text comment, kept enums and session ids
	`{"t":{"$date":"2026-11-01T10:00:02.000Z"},"s":"W","c":"COMMAND","id":51803,"ctx":"conn1","msg":"Slow query","attr":{"type":"command","ns":"bank.accounts","command":{"find":"accounts","filter":{"name":"SECRETJane"},"comment":"SECRET card 4111111111111111","lsid":{"id":{"$uuid":"3169e03a-f3e2-4119-9a6b-fcb879416c81"}},"readConcern":{"level":"majority"},"$db":"bank"},"planSummary":"IXSCAN { name: 1 }","durationMillis":150}}`,
	// duplicate key values in error text and keyValue
	`{"t":{"$date":"2026-11-01T10:00:03.000Z"},"s":"W","c":"QUERY","id":20526,"ctx":"conn3","msg":"Failed","attr":{"error":{"code":11000,"errmsg":"E11000 duplicate key error collection: bank.accounts index: phone_1 dup key: { phone: \"SECRET+1 555 0100\" }","keyPattern":{"phone":1},"keyValue":{"phone":"SECRET+1 555 0100"}}}}`,
	// host:port used as a key
	`{"t":{"$date":"2026-11-01T10:00:04.000Z"},"s":"I","c":"NETWORK","id":4333213,"ctx":"x","msg":"RSM Topology Change","attr":{"newTopologyDescription":{"servers":{"db1.secretcorp.com:27017":{"address":"db1.secretcorp.com:27017"}}}}}`,
	// LDAP query and an X.509 subject
	`{"t":{"$date":"2026-11-01T10:00:05.000Z"},"s":"I","c":"CONTROL","id":21951,"ctx":"main","msg":"Options set by command line","attr":{"options":{"security":{"ldap":{"userToDNMapping":"[{match: \"(.+)\", ldapQuery: \"dc=ads,dc=secretcorp,dc=com??sub?(sAMAccountName={0})\"}]"}}}}}`,
	`{"t":{"$date":"2026-11-01T10:00:06.000Z"},"s":"I","c":"NETWORK","id":23838,"ctx":"conn5","msg":"Peer certificate","attr":{"peerSubject":"CN=svc-app,OU=SaaS,O=SecretCorp Inc"}}`,
	// syslog prefix
	`Nov 01 10:00:07 db2.secretcorp.com mongod[1]: {"t":{"$date":"2026-11-01T10:00:07.000Z"},"s":"W","c":"COMMAND","id":51803,"ctx":"conn6","msg":"Slow query","attr":{"type":"command","ns":"bank.accounts","command":{"find":"accounts","filter":{"$and":[{"name":"SECRETJane"},{"city":"SECRETSpringfield"}]},"$db":"bank"},"durationMillis":150}}`,
}

var secrets = []string{"SECRET", "secretcorp", "SecretCorp", "jdoe", "4111111111111111", "203.0.113.7", "svc-app", "bank.accounts"}

func TestRunRemovesKnownLeaks(t *testing.T) {
	root := t.TempDir()
	in := filepath.Join(root, "in", "db1.secretcorp.com_mongod.log")
	if err := os.MkdirAll(filepath.Dir(in), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, []byte(strings.Join(leakLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	reg := registry.New()
	summary, err := Run(Config{Files: []inputs.File{{Path: in, Type: inputs.Log}}, InputRoot: filepath.Dir(in), OutputRoot: out, MappingPath: filepath.Join(root, "out_mapping.json"), Jobs: 1, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Outputs) != 1 || filepath.Base(summary.Outputs[0]) != "host1.domain1.example.com_mongod_obfuscated.log" {
		t.Fatalf("output name keeps the host name: %v", summary.Outputs)
	}
	data, err := os.ReadFile(summary.Outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			t.Errorf("%q remains in output", secret)
		}
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) != len(leakLines) {
		t.Fatalf("got %d lines, want %d", len(lines), len(leakLines))
	}
	for i, line := range lines {
		if j := strings.Index(line, `{"t"`); j >= 0 {
			line = line[j:]
		}
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %s", i+1, line)
		}
	}
	// diagnostic values are kept
	for _, want := range []string{`"$uuid":"3169e03a-f3e2-4119-9a6b-fcb879416c81"`, `"level":"majority"`, `"planSummary":"IXSCAN { name: 1 }"`, `"keyPattern":{"phone":1}`, `index: phone_1 dup key: { phone: \"obfuscated string\" }`, `"op":"u"`, `"diff":{"u":{"firstName":"obfuscated string","balance":0}}`, `mongod[1]: {"t"`} {
		if !strings.Contains(text, want) {
			t.Errorf("output lost %s", want)
		}
	}
	report, err := verify.Dir(out, verify.Options{Mapping: reg.Report()})
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 0 {
		t.Fatalf("verify found %d possible leaks: %+v", report.Total, report.Samples)
	}
	info, err := os.Stat(filepath.Join(root, "out_mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mapping mode %v, want 0600", info.Mode().Perm())
	}
}

// UUIDs identify connections, collections and index builds; they are kept
// whole even when their all-digit groups look like a card number.
func TestRunKeepsUUIDs(t *testing.T) {
	lines := []string{
		`{"t":{"$date":"2026-11-01T10:00:00.000Z"},"s":"I","c":"INDEX","id":20384,"ctx":"IndexBuildsCoordinatorMongod-0","msg":"Index build: starting","attr":{"ns":"shop.orders","buildUUID":{"uuid":{"$uuid":"61949369-6126-4783-8c4e-d2211f649f53"}},"collectionUUID":{"uuid":{"$uuid":"12340008-1234-1234-abcd-0123456789ab"}},"method":"Hybrid"}}`,
		`{"t":{"$date":"2026-11-01T10:00:01.000Z"},"s":"I","c":"STORAGE","id":20320,"ctx":"conn1","msg":"createCollection","attr":{"namespace":"shop.orders","uuidDisposition":"generated","uuid":{"uuid":{"$uuid":"abcdef01-abcd-ef01-1234-123456780002"}}}}`,
		`{"t":{"$date":"2026-11-01T10:00:02.000Z"},"s":"W","c":"INDEX","id":20441,"ctx":"conn2","msg":"Failed","attr":{"error":"index build 61949369-6126-4783-8c4e-d2211f649f53 aborted, card 4111 1111 1111 1111"}}`,
	}
	root := t.TempDir()
	in := filepath.Join(root, "in", "mongod.log")
	if err := os.MkdirAll(filepath.Dir(in), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	summary, err := Run(Config{Files: []inputs.File{{Path: in, Type: inputs.Log}}, InputRoot: filepath.Dir(in), OutputRoot: filepath.Join(root, "out"), MappingPath: filepath.Join(root, "out_mapping.json"), Jobs: 1, Registry: registry.New()})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(summary.Outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		`"buildUUID":{"uuid":{"$uuid":"61949369-6126-4783-8c4e-d2211f649f53"}}`,
		`"collectionUUID":{"uuid":{"$uuid":"12340008-1234-1234-abcd-0123456789ab"}}`,
		`"$uuid":"abcdef01-abcd-ef01-1234-123456780002"`,
		`index build 61949369-6126-4783-8c4e-d2211f649f53 aborted, card obfuscated-number`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lost %s\n%s", want, text)
		}
	}
	if strings.Contains(text, "4111") {
		t.Errorf("card number remains in output:\n%s", text)
	}
}

// Application names reported only in client metadata are mapped too; known
// tools keep their names.
func TestRunMapsClientMetadataAppNames(t *testing.T) {
	meta := func(conn, app string) string {
		return `{"t":{"$date":"2026-11-01T10:00:00.000Z"},"s":"I","c":"NETWORK","id":51800,"ctx":"` + conn + `","msg":"client metadata","attr":{"remote":"10.1.2.3:50000","client":"` + conn + `","doc":{"driver":{"name":"nodejs","version":"6.3.0"},"os":{"type":"Linux"},"application":{"name":"` + app + `"}}}}`
	}
	lines := []string{
		meta("conn1", "appd-mongo-dbagent-SECRETorg1-1-prod"),
		meta("conn2", "SECRET-orders-api"),
		meta("conn3", "mongosh 2.3.1"),
		meta("conn4", "pbm-agent"),
	}
	root := t.TempDir()
	in := filepath.Join(root, "in", "mongod.log")
	if err := os.MkdirAll(filepath.Dir(in), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	summary, err := Run(Config{Files: []inputs.File{{Path: in, Type: inputs.Log}}, InputRoot: filepath.Dir(in), OutputRoot: filepath.Join(root, "out"), MappingPath: filepath.Join(root, "out_mapping.json"), Jobs: 1, Registry: registry.New()})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(summary.Outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "SECRET") {
		t.Errorf("application name remains in output:\n%s", text)
	}
	for _, want := range []string{`"application":{"name":"app1"}`, `"application":{"name":"app2"}`, `"application":{"name":"mongosh 2.3.1"}`, `"application":{"name":"pbm-agent"}`} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %s:\n%s", want, text)
		}
	}
}
