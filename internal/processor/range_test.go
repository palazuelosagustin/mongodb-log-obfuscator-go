package processor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/registry"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/timerange"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func runRange(t *testing.T, root string, rng timerange.Range, files ...inputs.File) (Summary, *registry.Registry) {
	t.Helper()
	reg := registry.New()
	s, err := Run(Config{Files: files, InputRoot: root, OutputRoot: filepath.Join(root, "out"), MappingPath: filepath.Join(root, "out_mapping.json"), Jobs: 2, Registry: reg, Range: rng})
	if err != nil {
		t.Fatal(err)
	}
	return s, reg
}

func TestRangeKeepsLogLinesInside(t *testing.T) {
	root := t.TempDir()
	in := filepath.Join(root, "mongod.log")
	lines := []string{
		`{"t":{"$date":"2026-11-01T10:00:00.000+00:00"},"s":"I","c":"NETWORK","id":22943,"ctx":"l","msg":"Connection accepted","attr":{"remote":"203.0.113.50:1"}}`,
		`{"t":{"$date":"2026-11-01T08:30:00.000-03:00"},"s":"I","c":"NETWORK","id":22943,"ctx":"l","msg":"Connection accepted","attr":{"remote":"203.0.113.51:1"}}`, // 11:30Z
		`plain text without a timestamp`,
		`{"t":{"$date":"2026-11-01T12:00:00.000Z"},"s":"I","c":"NETWORK","id":22943,"ctx":"l","msg":"Connection accepted","attr":{"remote":"203.0.113.52:1"}}`,
	}
	if err := os.WriteFile(in, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, reg := runRange(t, root, timerange.Range{From: at("2026-11-01T10:30:00Z"), To: at("2026-11-01T12:00:00Z")}, inputs.File{Path: in, Type: inputs.Log})
	if s.OutOfRangeLines != 2 || len(s.Outputs) != 1 {
		t.Fatalf("out of range %d, outputs %v", s.OutOfRangeLines, s.Outputs)
	}
	data, _ := os.ReadFile(s.Outputs[0])
	out := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(out) != 2 || !strings.Contains(out[0], "08:30:00.000-03:00") || out[1] != "plain text without a timestamp" {
		t.Fatalf("output:\n%s", data)
	}
	// names seen only outside the range are not discovered
	if _, ok := reg.Categories["ip"]["203.0.113.50"]; ok {
		t.Fatal("an address outside the range was mapped")
	}

	empty := filepath.Join(root, "old.log")
	os.WriteFile(empty, []byte(lines[0]+"\n"), 0o644)
	s, _ = runRange(t, root, timerange.Range{From: at("2026-11-01T10:30:00Z")}, inputs.File{Path: empty, Type: inputs.Log})
	if len(s.NothingInRange) != 1 || s.Files != 0 {
		t.Fatalf("nothing in range %v, files %d", s.NothingInRange, s.Files)
	}
	if _, err := os.Stat(filepath.Join(root, "out", "old_obfuscated.log")); !os.IsNotExist(err) {
		t.Fatal("empty output kept")
	}
}

func ftdcDocAt(t *testing.T, typ int32, id time.Time) []byte {
	t.Helper()
	d := bson.D{{Key: "_id", Value: primitive.NewDateTimeFromTime(id)}, {Key: "type", Value: typ}}
	if typ == ftdc.TypeMetadata {
		d = append(d, bson.E{Key: "doc", Value: bson.D{{Key: "host", Value: "db1.corp.com"}}})
	} else {
		ref, _ := bson.Marshal(bson.D{{Key: "x", Value: int64(1)}})
		chunk, err := ftdc.RecompressMetricChunk(ftdc.MetricChunk{RefBSON: ref, MetricsCount: 1})
		if err != nil {
			t.Fatal(err)
		}
		d = append(d, bson.E{Key: "data", Value: primitive.Binary{Data: chunk}})
	}
	b, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRangeKeepsFTDCChunksThatOverlap(t *testing.T) {
	root := t.TempDir()
	t0 := at("2026-11-01T10:00:00Z")
	var data []byte
	data = append(data, ftdcDocAt(t, ftdc.TypeMetadata, t0)...)
	for i := 0; i < 4; i++ { // chunks at 10:00, 10:05, 10:10, 10:15
		data = append(data, ftdcDocAt(t, ftdc.TypeMetricChunk, t0.Add(time.Duration(i)*5*time.Minute))...)
	}
	in := filepath.Join(root, "metrics.1")
	os.WriteFile(in, data, 0o644)
	check := func(rng timerange.Range, want []time.Time, outOfRange int) {
		t.Helper()
		os.RemoveAll(filepath.Join(root, "out"))
		s, _ := runRange(t, root, rng, inputs.File{Path: in, Type: inputs.FTDC})
		if s.OutOfRangeChunks != outOfRange {
			t.Errorf("%v: out of range %d, want %d", rng, s.OutOfRangeChunks, outOfRange)
		}
		if len(want) == 0 {
			if len(s.NothingInRange) != 1 {
				t.Errorf("%v: expected nothing in range, got %v", rng, s.Outputs)
			}
			return
		}
		out, _ := os.ReadFile(s.Outputs[0])
		docs, err := ftdc.Iterate(out)
		if err != nil {
			t.Fatal(err)
		}
		if typ, _ := ftdc.Type(docs[0].Doc); typ != ftdc.TypeMetadata {
			t.Errorf("%v: metadata not first", rng)
		}
		var got []time.Time
		for _, d := range docs[1:] {
			id, _ := ftdc.ID(d.Doc)
			got = append(got, id)
		}
		if len(got) != len(want) {
			t.Fatalf("%v: chunks %v, want %v", rng, got, want)
		}
		for i := range got {
			if !got[i].Equal(want[i]) {
				t.Errorf("%v: chunks %v, want %v", rng, got, want)
			}
		}
	}
	m := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Minute) }
	check(timerange.Range{From: m(6), To: m(8)}, []time.Time{m(5)}, 3)
	check(timerange.Range{From: m(4), To: m(11)}, []time.Time{m(0), m(5), m(10)}, 1)
	check(timerange.Range{From: m(17)}, []time.Time{m(15)}, 3) // last chunk assumed to span 5 min
	check(timerange.Range{From: m(30)}, nil, 4)
}
