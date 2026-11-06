package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/processor"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/redact"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/verify"
)

// exitLeaks is the exit status when --verify or verify finds possible leaks.
const exitLeaks = 3

var errLeaks = errors.New("verify found possible leaks")

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		os.Exit(runVerifyCommand(os.Args[2:]))
	}
	args, ok := obfuscateArgs(os.Args[1:])
	if !ok {
		os.Exit(2)
	}
	if args == nil {
		return
	}
	if err := obfuscate(args); err != nil {
		if errors.Is(err, errLeaks) {
			fmt.Fprintf(os.Stderr, "Error: %v; do not share the output until they are checked\n", err)
			os.Exit(exitLeaks)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runVerifyCommand(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var mapping, mappingAlias string
	fs.StringVar(&mapping, "mapping", "", "mapping JSON written by the obfuscation")
	fs.StringVar(&mappingAlias, "m", "", "alias for --mapping")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if mapping == "" {
		mapping = mappingAlias
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mongodb-log-obfuscator-go verify [--mapping FILE] OUTPUT_DIR")
		return 2
	}
	dir := fs.Arg(0)
	if mapping == "" {
		if abs, err := filepath.Abs(dir); err == nil {
			mapping = defaultMappingPath(abs)
		}
	}
	reg := registry.New()
	if _, err := os.Stat(mapping); err == nil {
		if err := reg.Load(mapping); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintf(os.Stderr, "Warning: no mapping at %s; checking only emails, public IPs, card numbers and LDAP names\n", mapping)
		mapping = ""
	}
	if err := runVerify(dir, mapping, reg); err != nil {
		if errors.Is(err, errLeaks) {
			return exitLeaks
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func runVerify(dir, mappingPath string, reg *registry.Registry) error {
	report, err := verify.Dir(dir, verify.Options{Mapping: reg.Report(), MappingPath: mappingPath})
	if err != nil {
		return err
	}
	report.Write(os.Stderr)
	if report.Total > 0 {
		return fmt.Errorf("%w (%d)", errLeaks, report.Total)
	}
	return nil
}

// defaultMappingPath keeps the mapping next to the output directory, never
// inside it: whoever receives the output must not receive the mapping.
func defaultMappingPath(outputRoot string) string {
	return filepath.Clean(outputRoot) + "_mapping.json"
}

func inside(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func obfuscateArgs(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return nil, true
	}
	if args[0] == "obfuscate" {
		return args[1:], true
	}
	if strings.HasPrefix(args[0], "-") || looksLikeInput(args[0]) {
		return args, true
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
	usage()
	return nil, false
}

func looksLikeInput(arg string) bool {
	if strings.ContainsAny(arg, string(filepath.Separator)+".*?") {
		return true
	}
	_, err := os.Stat(arg)
	return err == nil
}
func obfuscate(args []string) error {
	fs := flag.NewFlagSet("obfuscate", flag.ExitOnError)
	var out, outAlias, mapping, mappingAlias, loadMapping, profile string
	var jobs int
	var dryRun, logOnly, ftdcOnly, doVerify, keepEquality bool
	fs.StringVar(&out, "out", "", "root directory for obfuscated output")
	fs.StringVar(&outAlias, "o", "", "alias for --out")
	fs.StringVar(&outAlias, "output-dir", "", "alias for --out")
	fs.StringVar(&mapping, "mapping", "", "path for shared mapping JSON")
	fs.StringVar(&mappingAlias, "m", "", "alias for --mapping")
	fs.StringVar(&loadMapping, "load-mapping", "", "load existing mapping JSON")
	fs.IntVar(&jobs, "jobs", runtime.NumCPU(), "parallel worker count")
	fs.StringVar(&profile, "profile", "", "directory for cpu.pprof and mem.pprof")
	fs.BoolVar(&dryRun, "dry-run", false, "discover and summarize without writing output")
	fs.BoolVar(&logOnly, "log-only", false, "process only log files")
	fs.BoolVar(&ftdcOnly, "ftdc-only", false, "process only FTDC files")
	fs.BoolVar(&doVerify, "verify", false, "check the output for possible leaks after writing it")
	fs.BoolVar(&keepEquality, "keep-equality", false, "replace redacted strings with keyed hashes so equal values stay equal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if out == "" {
		out = outAlias
	}
	if mapping == "" {
		mapping = mappingAlias
	}
	if logOnly && ftdcOnly {
		return fmt.Errorf("--log-only and --ftdc-only are mutually exclusive")
	}
	inputArgs := fs.Args()
	if len(inputArgs) == 0 {
		return fmt.Errorf("missing input path")
	}
	stopProfile, err := startProfile(profile)
	if err != nil {
		return err
	}
	if stopProfile != nil {
		defer stopProfile()
	}
	outputRoot, err := initialOutputRoot(inputArgs[0], out)
	if err != nil {
		return err
	}
	files, inputRoot, err := inputs.Resolve(inputArgs, outputRoot, inputs.Options{LogOnly: logOnly, FTDCOnly: ftdcOnly})
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no log or FTDC files found")
	}
	if out == "" {
		outputRoot = filepath.Join(inputRoot, "obfuscated")
	} else if outputRoot, err = filepath.Abs(out); err != nil {
		return err
	}
	if mapping == "" {
		mapping = defaultMappingPath(outputRoot)
	} else if mapping, err = filepath.Abs(mapping); err != nil {
		return err
	}
	if inside(mapping, outputRoot) {
		return fmt.Errorf("--mapping %s is inside the output directory %s; the mapping reverses the obfuscation and must be kept apart from the files you share", mapping, outputRoot)
	}
	if _, err := os.Stat(filepath.Join(outputRoot, "cluster_mapping.json")); err == nil {
		fmt.Fprintf(os.Stderr, "Warning: %s holds a mapping from an older version; delete it before sharing the directory\n", filepath.Join(outputRoot, "cluster_mapping.json"))
	}
	reg := registry.New()
	if loadMapping != "" {
		fmt.Fprintf(os.Stderr, "Loading existing mapping from %s\n", loadMapping)
		if err := reg.Load(loadMapping); err != nil {
			return err
		}
	}
	if keepEquality {
		if reg.EqualityKey == "" {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return err
			}
			reg.EqualityKey = hex.EncodeToString(key)
		}
		key, err := hex.DecodeString(reg.EqualityKey)
		if err != nil {
			return fmt.Errorf("equality key in mapping: %w", err)
		}
		redact.SetEqualityKey(key)
	}
	fmt.Fprintf(os.Stderr, "Input root:   %s\n", inputRoot)
	fmt.Fprintf(os.Stderr, "Output root:  %s\n", outputRoot)
	fmt.Fprintf(os.Stderr, "Mapping file: %s\n", mapping)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Found %d file(s)\n", len(files))
	start := time.Now()
	summary, err := processor.Run(processor.Config{Files: files, InputRoot: inputRoot, OutputRoot: outputRoot, MappingPath: mapping, Jobs: jobs, DryRun: dryRun, Registry: reg})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Discovered %d replacements in %s\n", summary.Replacements, summary.DiscoverTime.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "Payload redaction: enabled\n")
	if dryRun {
		fmt.Fprintf(os.Stderr, "Dry run complete. No files written.\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "Wrote %d file(s) in %s\n", summary.Files, summary.ReplaceTime.Round(time.Millisecond))
	if len(summary.Outputs) == 1 {
		fmt.Fprintf(os.Stderr, "Obfuscated file: %s\n", summary.Outputs[0])
	}
	fmt.Fprintf(os.Stderr, "Payload fields redacted: %d\n", summary.PayloadRedactions)
	fmt.Fprintf(os.Stderr, "Done in %s.\n", time.Since(start).Round(time.Millisecond))
	if doVerify {
		fmt.Fprintln(os.Stderr)
		return runVerify(outputRoot, mapping, reg)
	}
	return nil
}
func initialOutputRoot(firstInput, out string) (string, error) {
	if out != "" {
		return filepath.Abs(out)
	}
	info, err := os.Stat(firstInput)
	if err == nil && info.IsDir() {
		abs, err := filepath.Abs(firstInput)
		if err != nil {
			return "", err
		}
		return filepath.Join(abs, "obfuscated"), nil
	}
	abs, err := filepath.Abs(firstInput)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(abs), "obfuscated"), nil
}
func startProfile(dir string) (func(), error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cpu, err := os.Create(filepath.Join(dir, "cpu.pprof"))
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		cpu.Close()
		return nil, err
	}
	return func() {
		pprof.StopCPUProfile()
		cpu.Close()
		mem, err := os.Create(filepath.Join(dir, "mem.pprof"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: memory profile: %v\n", err)
			return
		}
		defer mem.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(mem); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: memory profile: %v\n", err)
		}
	}, nil
}
func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  mongodb-log-obfuscator-go [obfuscate] [flags] INPUT...

Flags:
  --out, -o, --output-dir DIR   Root directory for obfuscated output
  --mapping, -m FILE            Shared mapping JSON path
  --load-mapping FILE           Load an existing mapping JSON
  --jobs N                      Parallel worker count
  --profile DIR                 Write cpu.pprof and mem.pprof
  --dry-run                     Discover only; do not write output
  --log-only                    Process only log files
  --ftdc-only                   Process only FTDC files
  --verify                      Check the output for possible leaks (exit 3 if any)
  --keep-equality               Redacted strings become keyed hashes (obf_...): equal values stay equal

  mongodb-log-obfuscator-go verify [--mapping FILE] OUTPUT_DIR
                                Check an obfuscated directory; exit 3 on possible leaks

The mapping defaults to OUTPUT_DIR_mapping.json, next to the output directory
and never inside it: it reverses the obfuscation.
`)
}
