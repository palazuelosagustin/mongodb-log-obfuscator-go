# mongodb-log-obfuscator-go

Fast Go CLI for obfuscating MongoDB logs and FTDC diagnostic files with one
shared mapping across all inputs.

## Usage

```bash
go run ./cmd/mongodb-log-obfuscator-go /path/to/support-bundle
go run ./cmd/mongodb-log-obfuscator-go --out /tmp/sanitized --mapping /tmp/mapping.json /path/to/node1.log /path/to/diagnostic.data

# explicit subcommand form also works
go run ./cmd/mongodb-log-obfuscator-go obfuscate /path/to/support-bundle
```

Useful flags:

- `--out`, `-o`, `--output-dir`: output root. Defaults to `<common-input-root>/obfuscated`.
- `--mapping`, `-m`: mapping JSON path. Defaults to `<out>/cluster_mapping.json`.
- `--load-mapping`: seed replacements from an existing mapping.
- `--jobs`: parallel worker count.
- `--profile`: directory for `cpu.pprof` and `mem.pprof`.
- `--dry-run`: discover and summarize without writing output.
- `--log-only`, `--ftdc-only`: restrict input types.

Log files are written as `*_obfuscated.log`. FTDC files keep their original
relative names under the output root. Keep `cluster_mapping.json` private.

## Payload Redaction

Mapped replacements preserve coherent host, user, database, collection, and
namespace relationships. In addition, application payload fields inside MongoDB
command objects are redacted by default with the literal `obfuscated payload`.
This includes full values under fields such as `documents`, `updates`, `deletes`,
`query`, `filter`, `update`, `pipeline`, `let`, `q`, `u`, `template`,
`channelOptions`, `content`, `body`, `html`, `text`, `emailBody`, and `smsBody`
below `command`, `cmdObj`, and `originatingCommand` structures, including nested
truncated command data. These redactions are counted in the run summary but are
not written to `cluster_mapping.json`.

## Development

```bash
go test ./...
go test -bench . ./...
go vet ./...
go build ./cmd/mongodb-log-obfuscator-go
```
