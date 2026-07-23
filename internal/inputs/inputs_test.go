package inputs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSkipsObfuscatedAndComputesOutput(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mongod.log"), "x")
	mustWrite(t, filepath.Join(root, "mongod_obfuscated.log"), "x")
	mustWrite(t, filepath.Join(root, "obfuscated", "skip.log"), "x")
	mustWrite(t, filepath.Join(root, "diagnostic.data", "metrics.1"), string([]byte{5, 0, 0, 0, 0}))
	files, inputRoot, err := Resolve([]string{root}, filepath.Join(root, "obfuscated"), Options{})
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
