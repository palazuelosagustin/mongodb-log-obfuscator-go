package inputs

import (
	"bytes"
	"compress/gzip"
	"io"

	"fmt"
	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/ftdc"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

type FileType string

const (
	Log  FileType = "log"
	FTDC FileType = "ftdc"
)

type File struct {
	Path string
	Type FileType
	// Gzip marks a gzip-compressed log; its output is compressed too.
	Gzip bool
}

// Skipped is an input file that is not processed, and why.
type Skipped struct {
	Path   string
	Reason string
}

type Options struct {
	LogOnly  bool
	FTDCOnly bool
}

// Resolve finds the input files. Files that are not processed are returned
// in skipped with a reason, except hidden files, earlier outputs and mapping
// files, which are ignored.
func Resolve(args []string, excludeDir string, opts Options) ([]File, []Skipped, string, error) {
	var files []File
	var skipped []Skipped
	var roots []string
	for _, arg := range args {
		matches := []string{arg}
		if strings.ContainsAny(arg, "*?") {
			var err error
			matches, err = filepath.Glob(arg)
			if err != nil {
				return nil, nil, "", err
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
				return nil, nil, "", err
			}
			if info.IsDir() {
				roots = append(roots, abs)
				scanned, skips, err := scanDirectory(abs, excludeDir, opts)
				if err != nil {
					return nil, nil, "", err
				}
				files = append(files, scanned...)
				skipped = append(skipped, skips...)
				continue
			}
			if f, reason := classify(abs); reason != "" {
				if reason != ignore {
					skipped = append(skipped, Skipped{Path: abs, Reason: reason})
				}
			} else if allowed(f.Type, opts) {
				files = append(files, f)
			}
		}
	}
	files = dedupe(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	inputRoot := "."
	if len(roots) > 0 || len(files) > 0 {
		// Directories given and the directories of files given: the root
		// must contain every input so outputs stay below the output root.
		paths := append([]string(nil), roots...)
		for _, f := range files {
			paths = append(paths, filepath.Dir(f.Path))
		}
		inputRoot = commonPath(paths)
	} else if cwd, err := os.Getwd(); err == nil {
		inputRoot = cwd
	}
	return files, skipped, inputRoot, nil
}

func scanDirectory(root, excludeDir string, opts Options) ([]File, []Skipped, error) {
	var files []File
	var skipped []Skipped
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
		if !d.Type().IsRegular() {
			return nil
		}
		abs, _ := filepath.Abs(path)
		if f, reason := classify(abs); reason != "" {
			if reason != ignore {
				skipped = append(skipped, Skipped{Path: abs, Reason: reason})
			}
		} else if allowed(f.Type, opts) {
			files = append(files, f)
		}
		return nil
	})
	return files, skipped, err
}

func allowed(typ FileType, opts Options) bool {
	return !(opts.LogOnly && typ != Log) && !(opts.FTDCOnly && typ != FTDC)
}

// ignore is the reason of files skipped without a report.
const ignore = "-"

var archiveExts = []string{".tar.gz", ".tgz", ".tar", ".zip", ".bz2", ".xz", ".7z", ".rar", ".tar.bz2", ".tar.xz", ".zst"}

// classify decides from the name and the first bytes what a file is. A
// non-empty reason means the file is not processed.
func classify(path string) (File, string) {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") || base == "cluster_mapping.json" || strings.HasSuffix(base, "_mapping.json") || strings.Contains(base, "_obfuscated") || strings.Contains(path, "_obfuscated") {
		return File{}, ignore
	}
	for _, ext := range archiveExts {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			return File{}, "archive: extract it and run on the extracted files"
		}
	}
	head, err := readHead(path, 512)
	if err != nil {
		return File{}, "unreadable: " + err.Error()
	}
	if len(head) == 0 {
		return File{}, "empty"
	}
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		inner, err := gzipHead(path, 512)
		if err != nil {
			return File{}, "gzip: " + err.Error()
		}
		if !looksLikeText(inner) {
			return File{}, "gzip file that does not hold text"
		}
		return File{Path: path, Type: Log, Gzip: true}, ""
	}
	if ftdc.Sniff(head) {
		return File{Path: path, Type: FTDC}, ""
	}
	if !looksLikeText(head) {
		return File{}, "binary file that is not FTDC"
	}
	return File{Path: path, Type: Log}, ""
}

// looksLikeText accepts UTF-8 without NUL bytes and with few control
// characters (logs, configuration, command output).
func looksLikeText(head []byte) bool {
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	// a multi-byte character may be cut at the end of head
	for i := 0; i < utf8.UTFMax && len(head) > 0 && !utf8.Valid(head); i++ {
		head = head[:len(head)-1]
	}
	if !utf8.Valid(head) {
		return false
	}
	control := 0
	for _, b := range head {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' && b != '\f' && b != 0x1b {
			control++
		}
	}
	return control*100 <= len(head)
}

func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:m], nil
}

func gzipHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(zr, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:m], nil
}

func OutputPath(inputPath, inputRoot, outputRoot string, typ FileType) string {
	return filepath.Join(outputRoot, OutputRel(inputPath, inputRoot, typ))
}

// OutputRel is the output path relative to the output root. It never leaves
// the output root: a file outside inputRoot keeps only its base name.
func OutputRel(inputPath, inputRoot string, typ FileType) (out string) {
	rel, err := filepath.Rel(inputRoot, inputPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		rel = filepath.Base(inputPath)
	}
	if typ == FTDC {
		return rel
	}
	dir := filepath.Dir(rel)
	base := filepath.Base(rel)
	gz := strings.HasSuffix(base, ".gz")
	base = strings.TrimSuffix(base, ".gz")
	defer func() {
		if gz {
			out += ".gz"
		}
	}()
	if strings.HasSuffix(base, ".log") {
		base = strings.TrimSuffix(base, ".log") + "_obfuscated.log"
	} else {
		base += "_obfuscated"
	}
	out = filepath.Join(dir, base)
	return out
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
