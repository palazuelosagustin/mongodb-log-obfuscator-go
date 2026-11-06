# mongodb-log-obfuscator-go

Obfuscates MongoDB logs and FTDC diagnostic data before they are shared, for
example with an AI agent: host names, IP addresses, database, collection and
user names, and the personal data inside query payloads are replaced, while
what is needed to troubleshoot stays: query shapes and plans, latencies,
topology, replica-set states, metrics. One mapping is shared by all inputs, so
a host or collection has the same replacement in every log and FTDC file, and
`mongodb-logstat` and `mongodb-ftdcstat` read the output like the original.

## Install

Download the binary for your platform from the
[latest release](https://github.com/palazuelosagustin/mongodb-log-obfuscator-go/releases/latest)
(macOS and Linux, amd64 and arm64):

```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -fsSL "https://github.com/palazuelosagustin/mongodb-log-obfuscator-go/releases/latest/download/mongodb-log-obfuscator-go_${OS}_${ARCH}.tar.gz" | tar -xz mongodb-log-obfuscator-go
./mongodb-log-obfuscator-go --version
```

Move the binary to a directory on your `PATH`. A file downloaded with a
browser on macOS is quarantined; clear it with
`xattr -d com.apple.quarantine mongodb-log-obfuscator-go`. Each release lists
`checksums.txt` (SHA-256) for the archives. To build from source (Go 1.22+):
`go build -o mongodb-log-obfuscator-go ./cmd/mongodb-log-obfuscator-go`; a
source build reports `dev (<commit>)` as its version.

## Quick start

```bash
# obfuscate a case directory and check the result; exit status 3 means
# possible leaks: do not share the output until they are checked
mongodb-log-obfuscator-go --verify --out ~/cases/CS0012345/obfuscated ~/cases/CS0012345/raw

# share ~/cases/CS0012345/obfuscated; keep ~/cases/CS0012345/obfuscated_mapping.json
```

## What is guaranteed

- Values the tool discovers (hosts, IPs, databases, collections, users,
  replica sets, shards, paths, emails, application names, LDAP/X.509 names) are
  replaced everywhere, in values, host/path keys and file names, with the same
  replacement in every file.
- Inside commands, every string is replaced unless its key is on an
  allowlist of diagnostic values; filter, update, document and pipeline
  values are replaced; user documents are replaced wherever they are logged
  (replicated operations, duplicate-key errors, change streams).
- The mapping is never written inside the output directory, and `verify`
  reports one that is.
- Files that cannot be read or decoded are not copied: a failed file is not
  written, an undecodable FTDC document is dropped.

Best effort, and what `verify` cannot prove:

- Personal data in free text that is neither a discovered name nor a pattern
  `verify` checks (emails, public IPv4, card numbers, LDAP names): a person's
  name or phone number written into an error message by an application, for
  example. Such text is rare in MongoDB logs, but `verify` passing is evidence,
  not proof.
- Field names are kept (they carry the query shape), so a field such as
  `customerSsn` or one named after the company stays readable.
- Numbers outside filters and documents (pipeline stages other than `$match`,
  `$limit`, metrics) are kept.
- Lines that are not JSON get the mapping and the text patterns (payload
  keys, card numbers, duplicate-key values), not the structure-aware rules.

## Usage

```bash
mongodb-log-obfuscator-go /path/to/support-bundle
mongodb-log-obfuscator-go --out /tmp/sanitized --mapping /tmp/mapping.json /path/to/node1.log /path/to/diagnostic.data

# explicit subcommand form also works
mongodb-log-obfuscator-go obfuscate /path/to/support-bundle

# obfuscate, then check the output before sharing it (exit status 3 on possible leaks)
mongodb-log-obfuscator-go --verify /path/to/support-bundle

# check an obfuscated directory later
mongodb-log-obfuscator-go verify --mapping /path/to/obfuscated_mapping.json /path/to/obfuscated

mongodb-log-obfuscator-go --version
```

Useful flags:

- `--out`, `-o`, `--output-dir`: output root. Defaults to `<common-input-root>/obfuscated`.
- `--mapping`, `-m`: mapping JSON path. Defaults to `<out>_mapping.json`, next to
  the output directory. A path inside the output directory is rejected.
- `--load-mapping`: seed replacements from an existing mapping.
- `--jobs`: parallel workers (default: the CPU count). Files are processed in
  parallel, and large logs are split into blocks of lines processed in
  parallel and written in order, so one large log also uses every worker.
- `--profile`: directory for `cpu.pprof` and `mem.pprof`.
- `--dry-run`: discover and summarize without writing output.
- `--from TIME`, `--to TIME`: keep only the log lines and FTDC data of a time
  window, `--from` inclusive and `--to` exclusive, in the formats of
  `mongodb-logstat` and `mongodb-ftdcstat`: RFC3339 (`2026-11-04T13:30:00Z`,
  `2026-11-04T10:30:00-03:00`) or UTC without zone (`2026-11-04T13:30`,
  `2026-11-04`). See "Time range" below.
- `--log-only`, `--ftdc-only`: restrict input types.
- `--verify`: check the written output for possible leaks (see below).
- `--keep-equality`: redacted strings become keyed hashes (`obf_3f9a2c1b7d4e`)
  instead of one placeholder, so equal values stay equal (hot keys, skewed
  filters). The key is stored in the mapping; without it the hashes cannot be
  checked against guessed values. Use `--load-mapping` to hash later inputs the
  same way.

## Inputs

Files are recognised by content, not by name:

- FTDC: a BSON document starting with `_id`, wherever it is (`diagnostic.data`,
  renamed copies). A file that ends inside a document (the `metrics.interim`
  of a running mongod) keeps its complete documents, with a warning. FTDC
  documents that cannot be decoded are dropped with a warning, never copied.
- gzip-compressed logs (`mongod.log.1.gz`, `mongod.log-20261104.gz`): read
  compressed and written compressed (`mongod.log.1_obfuscated.gz`), one gzip
  member per block of lines so compression runs in parallel; `gzip -d`,
  `zcat` and Go/Python readers read it as one stream. Decompressing a gzip
  file uses one core, which bounds the speed on very large compressed logs.
- any other text file (logs, `mongod.conf`, command output): obfuscated as
  text, JSON log lines as JSON.

Skipped and listed with the reason: archives (`.tar.gz`, `.zip`, ... - extract
them first), binary files that are not FTDC, gzip files that do not hold
text, empty files. Hidden files, earlier outputs and mapping files are
ignored. A file that cannot be read is listed as failed and not written; the
other files are written and the exit status is 1. FTDC files are streamed
one document at a time, so memory does not grow with their size.

### Time range

With `--from`/`--to`, only what falls in the window is read closely and
written; the rest of each file is still read but not parsed, obfuscated or
written, so a narrow window over a large log is fast and the output small.

- Log lines are selected by their `"t"` timestamp. Lines without one
  (configuration files, command output) are kept.
- An FTDC metric chunk is kept when the time it covers (from its `_id` to the
  next chunk's) meets the window; the last chunk of a file is assumed to cover
  as long as the one before it. Metadata documents are kept before the first
  kept chunk, periodic metadata inside the window.
- Names that only appear outside the window are not discovered, so they are
  not in the mapping either.
- Files with nothing in the window are not written and are listed; the summary
  counts the log lines and FTDC chunks left out.

Log files are written as `*_obfuscated.log`. FTDC files keep their relative
paths under the output root. Mapped names in file and directory names are
replaced too (`db01.corp.com_mongod.log` becomes
`host1.example.com_mongod_obfuscated.log`), and nothing is written outside the
output root.

The mapping reverses the obfuscation. It is written with mode `0600` next to
the output directory, never inside it: share the output directory, keep the
mapping. A `cluster_mapping.json` left inside an output directory by an older
version is reported by `verify`; delete it before sharing.

## Mapped names

Each original gets one replacement, used everywhere (logs, FTDC, file names),
and replacements are applied in one pass, so a replacement is never replaced
again. When a value is seen in several roles, the most specific wins
(replica set, shard, database, collection, user, ... before free-text data).

Names keep the structure needed to read a topology:

| original | replacement |
|---|---|
| `db7.phx.corp.com`, `db8.phx.corp.com`, `db9.gso.corp.com` | `host1.zone1.domain1.example.com`, `host2.zone1.domain1.example.com`, `host3.zone2.domain1.example.com` |
| `db7` (short name of the same host) | `host1` |
| `mongo-rs0-0.mongo-rs0.psmdb.svc.cluster.local` | `host4.zone3.zone4.svc.cluster.local` |
| `203.0.113.7`, `203.0.113.9` | `198.18.0.7`, `198.18.0.9` (same /24, last octet kept) |
| `172.20.5.9` | `10.0.1.9` (private stays private) |

Public addresses map into 198.18.0.0/15 (then 100.64.0.0/10) and private ones
into 10.0.0.0/8; platform suffixes (`svc.cluster.local`, `compute.internal`,
`amazonaws.com`, `mongodb.net`, ...) are kept. Domain labels such as `phx` are
only replaced as part of a host or domain name.

Kept as they are, because they say what MongoDB or a tool was doing:
collections of `admin`, `local` and `config` (`oplog.rs`, `transactions`,
`pbmBackups`, ...), `system.*` collections, the `__system` user, application
names of MongoDB, Percona and common client tools (`pbm-agent`,
`mongodb_exporter`, `mongosh ...`, `MongoDB Compass`, `mongodump`, ...), and
Java classes of the JDK, MongoDB drivers and common frameworks in stack
traces. Host names in free text are only recognised with a known top-level
domain and in lowercase, so class names and versions are not taken for hosts.

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

After the mapping, a safety net replaces what still looks like a host name,
IP address, email or customer path in any kept string with
`obfuscated-host`, `192.0.2.1`, `obfuscated@example.com` or
`/obfuscated/path`: only the matched part, so messages stay readable.
Replacements made by the mapping, system and default MongoDB paths, JDK and
vendor names are left alone.

Every string inside a command is replaced unless its key is on a short list
of values needed for diagnosis: collection, database and user names (which are
mapped), index names, enum-like options (`readConcern.level`, `w`, `mode`,
collation, `verbosity`, ...), mongos client metadata and Extended JSON type
wrappers (`$uuid`, `$oid`, `$numberLong`, ...). `comment` and any other key
carrying application input are replaced.

Aggregation pipelines keep their structure: `$match` (and `$geoNear`,
`$search`, ...) is redacted like any filter; in other stages field references
(`"$amount"`, `"$$ROOT"`), numbers (`$limit`, `$sort`, `$project` flags) and
booleans are kept, `$lookup`/`$graphLookup` field names are kept, the
collections of `$lookup`, `$unionWith`, `$out` and `$merge` are mapped, and any
other string is replaced.

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

## Versions and releases

Releases follow [semantic versioning](https://semver.org/). Until `v1.0.0`, a
minor release (`v0.2.0`) changes what is obfuscated or kept, or adds flags,
and a patch release (`v0.1.1`) only fixes bugs. A leak fix is always released
promptly. `--version` prints the version, commit and build date; the mapping
records the version that wrote it (`_meta.toolVersion`). Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

To release: move the `Unreleased` entries in `CHANGELOG.md` under the new
version, commit, then tag and push the tag:

```bash
git tag -a v0.2.0 -m v0.2.0
git push origin v0.2.0
```

The `release` GitHub Actions workflow runs the tests and publishes the
archives with [GoReleaser](https://goreleaser.com/) (`.goreleaser.yaml`). Check
the config locally with `goreleaser release --snapshot --clean`.

## Agent skill

`skills/.claude/mongodb-log-obfuscator-go/` is a Claude Code skill (with the
same text for Codex in `skills/.codex/mongodb-log-obfuscator-go/`) that tells
an agent to obfuscate and verify customer logs before reading them, and how to
use the output with `mongodb-logstat` and `mongodb-ftdcstat`. Install it with:

```bash
ln -s ~/bin/mongodb-log-obfuscator-go/skills/.claude/mongodb-log-obfuscator-go ~/.claude/skills/mongodb-log-obfuscator-go
```

## Development

```bash
go test ./...
go test -bench . ./...
go vet ./...
go build -o mongodb-log-obfuscator-go ./cmd/mongodb-log-obfuscator-go
```
