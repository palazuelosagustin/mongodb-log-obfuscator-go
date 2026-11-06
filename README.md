# mongodb-log-obfuscator-go

Fast Go CLI for obfuscating MongoDB logs and FTDC diagnostic files with one
shared mapping across all inputs.

## Usage

```bash
go run ./cmd/mongodb-log-obfuscator-go /path/to/support-bundle
go run ./cmd/mongodb-log-obfuscator-go --out /tmp/sanitized --mapping /tmp/mapping.json /path/to/node1.log /path/to/diagnostic.data

# explicit subcommand form also works
go run ./cmd/mongodb-log-obfuscator-go obfuscate /path/to/support-bundle

# obfuscate, then check the output before sharing it (exit status 3 on possible leaks)
go run ./cmd/mongodb-log-obfuscator-go --verify /path/to/support-bundle

# check an obfuscated directory later
go run ./cmd/mongodb-log-obfuscator-go verify --mapping /path/to/obfuscated_mapping.json /path/to/obfuscated
```

Useful flags:

- `--out`, `-o`, `--output-dir`: output root. Defaults to `<common-input-root>/obfuscated`.
- `--mapping`, `-m`: mapping JSON path. Defaults to `<out>_mapping.json`, next to
  the output directory. A path inside the output directory is rejected.
- `--load-mapping`: seed replacements from an existing mapping.
- `--jobs`: parallel worker count.
- `--profile`: directory for `cpu.pprof` and `mem.pprof`.
- `--dry-run`: discover and summarize without writing output.
- `--log-only`, `--ftdc-only`: restrict input types.
- `--verify`: check the written output for possible leaks (see below).

Log files are written as `*_obfuscated.log`. FTDC files keep their relative
paths under the output root. Mapped names in file and directory names are
replaced too (`db01.corp.com_mongod.log` becomes
`host1.example.com_mongod_obfuscated.log`), and nothing is written outside the
output root.

The mapping reverses the obfuscation. It is written with mode `0600` next to
the output directory, never inside it: share the output directory, keep the
mapping. A `cluster_mapping.json` left inside an output directory by an older
version is reported by `verify`; delete it before sharing.

## Verify

`--verify` (after obfuscating) and `verify OUTPUT_DIR` (on an existing
directory) read every output file, including the decompressed FTDC metric
chunks, and report:

- originals from the mapping still present in a value, or in a key for hosts,
  IPs, paths and emails (field names equal to a collection name are kept by
  design);
- emails outside `example.com`, public IPv4 addresses, payment card numbers
  (13-19 digits passing the Luhn check) and LDAP/X.509 names (`dc=`, `cn=`,
  `uid=`, `o=`) that are not replacements;
- mapping files inside the directory.

Findings are printed without the values: a mapped original is named by its
replacement, other values are masked (`j…(17 chars)`), so the report can be
shown to an agent. The exit status is `3` when anything is found. Verify only
knows the mapping and these patterns: a name or phone number that was never
discovered is not detected, so a clean result is evidence, not proof.

## Payload Redaction

Mapped replacements preserve coherent host, user, database, collection, and
namespace relationships. In addition, application payload fields inside MongoDB
command objects are obfuscated by default while preserving query and update
shape. Structured JSON logs and FTDC BSON keep field names, MongoDB operators,
object nesting, array lengths, and command collection names; only scalar payload
values are replaced with type-safe placeholders such as `obfuscated string`, `0`,
`false`, and valid Extended JSON placeholders like `1970-01-01T00:00:00Z` for
`$date` values.

Every string inside a command is replaced unless its key is on a short list
of values needed for diagnosis: collection, database and user names (which are
mapped), index names, enum-like options (`readConcern.level`, `w`, `mode`,
collation, `verbosity`, ...), mongos client metadata and Extended JSON type
wrappers (`$uuid`, `$oid`, `$numberLong`, ...). `comment` and any other key
carrying application input are replaced.

User documents are redacted wherever they appear, not only in commands:
replicated operations (`o`, `o2` in "Applied op" lines), duplicate-key values
(`keyValue` and the `dup key: { ... }` text of error messages), change-stream
images (`fullDocument`, `updateDescription`, ...). Card numbers in any free
text are replaced. Host, IP and path keys (topology descriptions, connection
pools, listener sockets) are mapped like values. Lines with a syslog/journald,
`kubectl --timestamps` or `docker logs` prefix are parsed as JSON; the prefix is
mapped as text. X.509 subjects are replaced whole, and LDAP `dc=`, `o=`, `cn=`
and `uid=` values are mapped.

This includes scalar values under fields such as `documents`, `updates`,
`deletes`, `query`, `filter`, `update`, `pipeline`, `let`, `q`, `u`, `template`,
`channelOptions`, `content`, `body`, `html`, `text`, `emailBody`, and `smsBody`
below `command`, `cmdObj`, and `originatingCommand` structures, including nested
truncated command data. These redactions are counted in the run summary but are
not written to `cluster_mapping.json`. Non-JSON log fallback redaction remains
best-effort text redaction and does not guarantee query-pattern preservation.

## Development

```bash
go test ./...
go test -bench . ./...
go vet ./...
go build ./cmd/mongodb-log-obfuscator-go
```
