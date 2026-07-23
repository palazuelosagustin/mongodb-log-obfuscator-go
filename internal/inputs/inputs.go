package inputs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FileType string

const (
	Log  FileType = "log"
	FTDC FileType = "ftdc"
)

type File struct {
	Path string
	Type FileType
}

type Options struct {
	LogOnly  bool
	FTDCOnly bool
}

func Resolve(args []string, excludeDir string, opts Options) ([]File, string, error) {
	var files []File
	var roots []string
	for _, arg := range args {
		matches := []string{arg}
		if strings.ContainsAny(arg, "*?") {
			var err error
			matches, err = filepath.Glob(arg)
			if err != nil {
				return nil, "", err
			}
		}
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: %s not found, skipping\n", match)
				continue
			}
			abs, err := filepath.Abs(match)
			if err != nil {
				return nil, "", err
			}
			if info.IsDir() {
				roots = append(roots, abs)
				scanned, err := scanDirectory(abs, excludeDir, opts)
				if err != nil {
					return nil, "", err
				}
				files = append(files, scanned...)
				continue
			}
			if typ := classify(abs); typ != "" && allowed(typ, opts) {
				files = append(files, File{Path: abs, Type: typ})
			}
		}
	}
	files = dedupe(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	inputRoot := "."
	if len(roots) > 0 {
		inputRoot = commonPath(roots)
	} else if len(files) > 0 {
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = filepath.Dir(f.Path)
		}
		inputRoot = commonPath(paths)
	} else if cwd, err := os.Getwd(); err == nil {
		inputRoot = cwd
	}
	return files, inputRoot, nil
}

func scanDirectory(root, excludeDir string, opts Options) ([]File, error) {
	var files []File
	excludeDir, _ = filepath.Abs(excludeDir)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := filepath.Base(path)
		if d.IsDir() {
			abs, _ := filepath.Abs(path)
			if path != root && (strings.HasPrefix(base, ".") || base == "obfuscated" || (excludeDir != "" && abs == excludeDir)) {
				return filepath.SkipDir
			}
			return nil
		}
		if typ := classify(path); typ != "" && allowed(typ, opts) {
			abs, _ := filepath.Abs(path)
			files = append(files, File{Path: abs, Type: typ})
		}
		return nil
	})
	return files, err
}

func allowed(typ FileType, opts Options) bool {
	return !(opts.LogOnly && typ != Log) && !(opts.FTDCOnly && typ != FTDC)
}

func classify(path string) FileType {
	base := filepath.Base(path)
	parent := filepath.Base(filepath.Dir(path))
	if strings.HasPrefix(base, ".") || base == "cluster_mapping.json" || strings.Contains(base, "_obfuscated") || strings.Contains(path, "_obfuscated") {
		return ""
	}
	for _, ext := range []string{".tar.gz", ".tgz", ".tar", ".gz", ".zip", ".bz2", ".xz", ".7z", ".rar"} {
		if strings.HasSuffix(base, ext) {
			return ""
		}
	}
	if parent == "diagnostic.data" || strings.HasSuffix(base, ".ftdc") || strings.HasPrefix(base, "metrics.") || base == "metrics" {
		return FTDC
	}
	if strings.HasSuffix(base, ".log") {
		return Log
	}
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 && bytes.Contains(b[:min(len(b), 256)], []byte{0}) {
		return FTDC
	}
	return Log
}

func OutputPath(inputPath, inputRoot, outputRoot string, typ FileType) string {
	rel, err := filepath.Rel(inputRoot, inputPath)
	if err != nil {
		rel = filepath.Base(inputPath)
	}
	if typ == FTDC {
		return filepath.Join(outputRoot, rel)
	}
	dir := filepath.Dir(rel)
	base := filepath.Base(rel)
	if strings.HasSuffix(base, ".log") {
		base = strings.TrimSuffix(base, ".log") + "_obfuscated.log"
	} else {
		base += "_obfuscated"
	}
	return filepath.Join(outputRoot, dir, base)
}

func dedupe(files []File) []File {
	seen := map[string]struct{}{}
	out := files[:0]
	for _, f := range files {
		if _, ok := seen[f.Path]; ok {
			continue
		}
		seen[f.Path] = struct{}{}
		out = append(out, f)
	}
	return out
}

func commonPath(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	common := paths[0]
	for _, p := range paths[1:] {
		for common != "/" && common != "." {
			rel, err := filepath.Rel(common, p)
			if err == nil && !strings.HasPrefix(rel, "..") {
				break
			}
			common = filepath.Dir(common)
		}
	}
	return common
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
