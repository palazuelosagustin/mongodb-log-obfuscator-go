// Package version holds the release version of mongodb-log-obfuscator-go. Release
// builds set Version, Commit and Date with -ldflags -X; a plain `go build`
// reports "dev" plus the VCS revision Go embeds in the binary.
package version

import (
	"fmt"
	"runtime/debug"
)

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String is the version as printed by --version and written to JSON, for
// example "v0.1.0" or "dev (3f2c1ab, modified)".
func String() string {
	if Version != "dev" {
		return Version
	}
	commit, modified := Commit, false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	commit = shortCommit(commit)
	switch {
	case commit == "":
		return "dev"
	case modified:
		return fmt.Sprintf("dev (%s, modified)", commit)
	default:
		return fmt.Sprintf("dev (%s)", commit)
	}
}

// Long is the --version line: version, then commit and build date for
// release builds.
func Long(name string) string {
	s := name + " " + String()
	if Version != "dev" && Commit != "" {
		s += " (" + shortCommit(Commit)
		if Date != "" {
			s += ", " + Date
		}
		s += ")"
	}
	return s
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}
