package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/inputs"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/processor"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		return
	}
	if os.Args[1] != "obfuscate" {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err := obfuscate(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
func obfuscate(args []string) error {
	fs := flag.NewFlagSet("obfuscate", flag.ExitOnError)
	var out, outAlias, mapping, mappingAlias, loadMapping, profile string
	var jobs int
	var dryRun, logOnly, ftdcOnly bool
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
		mapping = filepath.Join(outputRoot, "cluster_mapping.json")
	} else if mapping, err = filepath.Abs(mapping); err != nil {
		return err
	}
	reg := registry.New()
	if loadMapping != "" {
		fmt.Fprintf(os.Stderr, "Loading existing mapping from %s\n", loadMapping)
		if err := reg.Load(loadMapping); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Input root:   %s\n", inputRoot)
	fmt.Fprintf(os.Stderr, "Output root:  %s\n", outputRoot)
	fmt.Fprintf(os.Stderr, "Mapping file: %s\n", mapping)
	if len(files) == 1 {
		fmt.Fprintf(os.Stderr, "Obfuscated file: %s\n", inputs.OutputPath(files[0].Path, inputRoot, outputRoot, files[0].Type))
	}
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
	fmt.Fprintf(os.Stderr, "Payload fields redacted: %d\n", summary.PayloadRedactions)
	fmt.Fprintf(os.Stderr, "Done in %s.\n", time.Since(start).Round(time.Millisecond))
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
  mongodb-log-obfuscator-go obfuscate [flags] INPUT...

Flags:
  --out, -o, --output-dir DIR   Root directory for obfuscated output
  --mapping, -m FILE            Shared mapping JSON path
  --load-mapping FILE           Load an existing mapping JSON
  --jobs N                      Parallel worker count
  --profile DIR                 Write cpu.pprof and mem.pprof
  --dry-run                     Discover only; do not write output
  --log-only                    Process only log files
  --ftdc-only                   Process only FTDC files
`)
}
