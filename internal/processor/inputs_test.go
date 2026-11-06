package processor

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func runFiles(t *testing.T, root string, files ...inputs.File) Summary {
	t.Helper()
	summary, err := Run(Config{Files: files, InputRoot: root, OutputRoot: filepath.Join(root, "out"), MappingPath: filepath.Join(root, "out_mapping.json"), Jobs: 2, Registry: registry.New()})
	if err != nil {
		t.Fatal(err)
	}
	return summary
}

func TestTruncatedFTDCKeepsCompleteDocuments(t *testing.T) {
	root := t.TempDir()
	full := buildFTDC(t, []byte{1, 2, 3})
	path := filepath.Join(root, "metrics.interim")
	if err := os.WriteFile(path, append(full, full[:20]...), 0o644); err != nil {
		t.Fatal(err)
	}
	s := runFiles(t, root, inputs.File{Path: path, Type: inputs.FTDC})
	if len(s.Failures) != 0 || len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0].Message, "truncated") {
		t.Fatalf("failures %v, warnings %v", s.Failures, s.Warnings)
	}
	out, err := os.ReadFile(s.Outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ftdc.Iterate(out)
	if err != nil || len(docs) != 2 {
		t.Fatalf("docs %d, err %v", len(docs), err)
	}
}

func TestUndecodableFTDCDocumentsAreDropped(t *testing.T) {
	root := t.TempDir()
	bad, err := bson.Marshal(bson.D{{Key: "type", Value: int32(ftdc.TypeMetricChunk)}, {Key: "data", Value: primitive.Binary{Data: []byte("\x10\x00\x00\x00not zlib db9.secretcorp.com")}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "metrics.1")
	if err := os.WriteFile(path, append(buildFTDC(t, []byte{1}), bad...), 0o644); err != nil {
		t.Fatal(err)
	}
	s := runFiles(t, root, inputs.File{Path: path, Type: inputs.FTDC})
	out, err := os.ReadFile(s.Outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("secretcorp")) {
		t.Fatal("undecodable document copied")
	}
	dropped := false
	for _, w := range s.Warnings {
		dropped = dropped || strings.Contains(w.Message, "dropped")
	}
	if !dropped {
		t.Fatalf("no warning about the dropped document: %v", s.Warnings)
	}
}

func TestGzipLogIsReadAndWrittenCompressed(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(strings.Join(leakLines, "\n") + "\n"))
	zw.Close()
	path := filepath.Join(root, "mongod.log.1.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(root, "broken.log.gz")
	if err := os.WriteFile(broken, buf.Bytes()[:40], 0o644); err != nil {
		t.Fatal(err)
	}
	s := runFiles(t, root, inputs.File{Path: path, Type: inputs.Log, Gzip: true}, inputs.File{Path: broken, Type: inputs.Log, Gzip: true})
	if len(s.Failures) != 1 || filepath.Base(s.Failures[0].Path) != "broken.log.gz" || len(s.Outputs) != 1 {
		t.Fatalf("failures %v, outputs %v", s.Failures, s.Outputs)
	}
	if !strings.HasSuffix(s.Outputs[0], "mongod.log.1_obfuscated.gz") {
		t.Fatalf("output %s", s.Outputs[0])
	}
	f, err := os.Open(s.Outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	text, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(text), "\n") != len(leakLines) {
		t.Fatalf("lines lost: %s", text)
	}
	for _, secret := range secrets {
		if strings.Contains(string(text), secret) {
			t.Errorf("%q remains", secret)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "out", "broken.log_obfuscated.gz")); !os.IsNotExist(err) {
		t.Fatalf("partial output of the failed file kept: %v", err)
	}
}
