package inputs

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSkipsObfuscatedAndComputesOutput(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mongod.log"), "x")
	mustWrite(t, filepath.Join(root, "mongod_obfuscated.log"), "x")
	mustWrite(t, filepath.Join(root, "obfuscated", "skip.log"), "x")
	mustWrite(t, filepath.Join(root, "diagnostic.data", "metrics.1"), ftdcDoc)
	files, _, inputRoot, err := Resolve([]string{root}, filepath.Join(root, "obfuscated"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if inputRoot != root {
		t.Fatalf("inputRoot = %q, want %q", inputRoot, root)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2: %#v", len(files), files)
	}
	out := OutputPath(filepath.Join(root, "mongod.log"), root, filepath.Join(root, "out"), Log)
	if filepath.Base(out) != "mongod_obfuscated.log" {
		t.Fatalf("log output path = %q", out)
	}
	ftdcOut := OutputPath(filepath.Join(root, "diagnostic.data", "metrics.1"), root, filepath.Join(root, "out"), FTDC)
	if filepath.Base(ftdcOut) != "metrics.1" {
		t.Fatalf("ftdc output path = %q", ftdcOut)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveFileAndDirectoryStayBelowOutputRoot(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "case", "mongod.log")
	ftdcPath := filepath.Join(root, "case", "diag", "diagnostic.data", "metrics.1")
	mustWrite(t, logPath, "{}\n")
	mustWrite(t, ftdcPath, ftdcDoc)
	files, _, inputRoot, err := Resolve([]string{logPath, filepath.Dir(filepath.Dir(ftdcPath))}, filepath.Join(root, "out"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
	for _, f := range files {
		if rel := OutputRel(f.Path, inputRoot, f.Type); strings.HasPrefix(rel, "..") {
			t.Fatalf("%s would be written outside the output root: %s", f.Path, rel)
		}
	}
	if got := OutputRel("/elsewhere/x.log", inputRoot, Log); got != "x_obfuscated.log" {
		t.Fatalf("outside file maps to %q", got)
	}
}

// ftdcDoc is the smallest FTDC-like document: {_id: Date(0)}.
var ftdcDoc = string([]byte{18, 0, 0, 0, 0x09, '_', 'i', 'd', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

func TestResolveReportsSkippedFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mongod.log"), "{}\n")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("{}\n"))
	zw.Close()
	mustWrite(t, filepath.Join(root, "mongod.log.1.gz"), gz.String())
	mustWrite(t, filepath.Join(root, "logs.tar.gz"), gz.String())
	mustWrite(t, filepath.Join(root, "core.bin"), "\x7fELF\x00\x01")
	random := make([]byte, 512)
	for i := range random {
		random[i] = byte(1 + (i*97+13)%255) // no NUL byte, not text
	}
	mustWrite(t, filepath.Join(root, "noise.dat"), string(random))
	mustWrite(t, filepath.Join(root, "empty.log"), "")
	mustWrite(t, filepath.Join(root, "metrics.2026"), ftdcDoc) // FTDC outside diagnostic.data
	mustWrite(t, filepath.Join(root, "mongod.conf"), "net:\n  bindIp: db1.corp.com\n")
	mustWrite(t, filepath.Join(root, ".DS_Store"), "\x00")
	files, skipped, _, err := Resolve([]string{root}, filepath.Join(root, "out"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[filepath.Base(f.Path)] = string(f.Type)
		if f.Gzip {
			got[filepath.Base(f.Path)] += "+gzip"
		}
	}
	for _, s := range skipped {
		got[filepath.Base(s.Path)] = "skipped: " + s.Reason
	}
	want := map[string]string{
		"mongod.log":      "log",
		"mongod.log.1.gz": "log+gzip",
		"logs.tar.gz":     "skipped: archive: extract it and run on the extracted files",
		"core.bin":        "skipped: binary file that is not FTDC",
		"noise.dat":       "skipped: binary file that is not FTDC",
		"empty.log":       "skipped: empty",
		"metrics.2026":    "ftdc",
		"mongod.conf":     "log",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %q, want %q", name, got[name], w)
		}
	}
	if _, ok := got[".DS_Store"]; ok {
		t.Errorf("hidden file reported: %v", got)
	}
	if out := OutputRel(filepath.Join(root, "mongod.log.1.gz"), root, Log); out != "mongod.log.1_obfuscated.gz" {
		t.Errorf("gzip output name %q", out)
	}
	if out := OutputRel(filepath.Join(root, "mongod.log.gz"), root, Log); out != "mongod_obfuscated.log.gz" {
		t.Errorf("gzip output name %q", out)
	}
}
