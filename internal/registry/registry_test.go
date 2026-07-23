package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryWriteLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mapping.json")
	r := New()
	got := r.GetOrCreate("hostname", "prod-host")
	if got != "host1" {
		t.Fatalf("replacement = %q", got)
	}
	if err := r.Write(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	r2 := New()
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	if r2.GetOrCreate("hostname", "prod-host") != "host1" {
		t.Fatal("mapping not loaded")
	}
	if r2.GetOrCreate("hostname", "other-host") != "host2" {
		t.Fatal("counter not preserved")
	}
}
