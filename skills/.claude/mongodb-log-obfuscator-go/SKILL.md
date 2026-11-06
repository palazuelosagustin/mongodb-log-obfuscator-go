---
name: mongodb-log-obfuscator-go
description: Obfuscate customer MongoDB / Percona Server for MongoDB logs and FTDC diagnostic.data with mongodb-log-obfuscator-go before anyone, including the agent, reads or shares them, and check the result. Use as the first step before running mongodb-logstat or mongodb-ftdcstat on customer data; when the user has a support bundle, mongod/mongos logs or diagnostic.data to anonymize, obfuscate, sanitize or redact; needs consistent pseudonyms across nodes or batches; wants obfuscated output checked for leaked host names, IPs, users, namespaces or query values; asks about the obfuscator's output, mapping or exit status; or is changing the obfuscator's code. Not for analysing the logs (use mongodb-logstat and mongodb-ftdcstat on the obfuscated output) or for other databases.
---

# mongodb-log-obfuscator-go

`mongodb-log-obfuscator-go` replaces host names, IPs, database, collection and
user names and the personal data in query payloads of MongoDB logs and FTDC,
and keeps what troubleshooting needs (query shapes, plans, latencies,
topology, metrics). The output reads in `mongodb-logstat` and
`mongodb-ftdcstat` like the original.

## Rules

1. **Do not read raw case files.** Before obfuscation, do not `cat`, `head`,
   `grep`, `jq` or open customer logs, FTDC or config files: whatever you read
   enters the conversation. Pass their paths to the obfuscator only. Listing
   names and sizes (`ls`, `du`) and extracting archives (`tar -xf` into the raw
   directory) is fine.
2. **Never read the mapping.** `*_mapping.json` reverses the obfuscation. Do
   not open, print, `jq` or summarise it; only pass it to `verify --mapping` or
   `--load-mapping`.
3. **Read only output that passed verify.** Run with `--verify` and read the
   output directory only after exit status 0.
4. **Translating back is the user's step.** When a finding has to name the
   real host or collection for the customer, give the user a command to run
   themselves, for example
   `jq -r '.fqdn | to_entries[] | select(.value=="host2.zone1.domain1.example.com") | .key' CASE/obfuscated_mapping.json`,
   and do not run it.

## Locating the binary

1. `command -v mongodb-log-obfuscator-go`
2. Otherwise download the latest release:
   `https://github.com/palazuelosagustin/mongodb-log-obfuscator-go/releases/latest/download/mongodb-log-obfuscator-go_<darwin|linux>_<arm64|amd64>.tar.gz`
   (see README Install)
3. Otherwise build into a scratch path from the repo root:
   `go build -o /tmp/mongodb-log-obfuscator-go ./cmd/mongodb-log-obfuscator-go`

`mongodb-log-obfuscator-go --version` names the build; the mapping records it
too.

## Working order

1. Find the raw inputs by name: `mongod.log*`, `mongos.log*`, `*.log.gz`,
   `diagnostic.data/`, pod log directories. Extract archives first; they are
   skipped otherwise.
2. Obfuscate into a directory next to the raw data:

   ```bash
   mongodb-log-obfuscator-go --verify --out CASE/obfuscated CASE/raw
   ```

   Several inputs (files, directories, globs) share one mapping:
   `mongodb-log-obfuscator-go --verify --out CASE/obfuscated CASE/node1.log CASE/node2/diagnostic.data`.
   Run all nodes of a cluster in **one** invocation (or chain runs with
   `--load-mapping`, step 5): separate runs number names independently, so
   `host1` in one output would not be `host1` in another.
   `--dry-run` lists what would be processed and skipped without writing
   anything, not even the mapping.
   Add `--keep-equality` when equal values must stay recognisable (hot keys,
   skewed filters, the same document updated repeatedly).
   When the incident window is known, add `--from`/`--to` (same formats as
   `mongodb-logstat`; `--from` inclusive, `--to` exclusive) with some margin
   before and after: less is exposed, and a large log is done much faster.
   Lines without a timestamp are kept; files with nothing in the window are
   listed as not written.
3. Read the exit status and the stderr summary:

   | exit | meaning | do |
   |---|---|---|
   | 0 | written, verify clean | analyse `CASE/obfuscated` |
   | 3 | verify found possible leaks | show the user the masked report; do not read the output until they decide |
   | 1 | some files failed (listed, not written) or a usage error | report the list; the other files were written and verified only if the run reached verify |
   | 2 | bad arguments | fix the command |

   "Skipped N file(s)" lists archives, binaries and empty files with the
   reason; mention them if they could matter (an archive of rotated logs).
4. Analyse the output with `mongodb-logstat` and `mongodb-ftdcstat`. Names
   look like `host2.zone1.domain1.example.com`, `database1.collection8`,
   `replset1`, `user3`, `10.0.1.7`; redacted values are `obfuscated string`
   (or `obf_…` with `--keep-equality`), numbers in filters `0`, dates
   `1970-01-01T00:00:00Z`.
5. More files from the same case later: reuse the mapping so names stay the
   same, writing to a new output directory:
   `mongodb-log-obfuscator-go --verify --load-mapping CASE/obfuscated_mapping.json --mapping CASE/obfuscated2_mapping.json --out CASE/obfuscated2 CASE/raw2`.

## Reading obfuscated output

- **Topology survives.** Hosts of one site or Kubernetes service share a
  suffix (`zone1`), a short name and its FQDN share the host number, IPs keep
  their /24 and last octet, private stays in `10/8`, public maps to
  `198.18/15` or `100.64/10`.
- **Kept as is:** `admin`, `local`, `config` and `system.*` collections
  (`oplog.rs`, `pbmBackups`), tool application names (`pbm-agent`,
  `mongodb_exporter`, `mongosh`), `__system`, JDK and framework classes,
  field names, operators, plan summaries, query shape hashes, metrics.
- **Replaced inside commands:** every string except collection, database and
  user names (mapped), index names and enum-like options (`readConcern.level`,
  `w`, `mode`). `comment` is replaced.
- **Pipelines:** `$match` is redacted; other stages keep field references
  (`"$amount"`), numbers and `$lookup` field names; their collections are
  mapped.
- **Safety net:** after the mapping, what still looks like a host name, IP,
  email or customer path in text is replaced by `obfuscated-host`,
  `192.0.2.1`, `obfuscated@example.com` or `/obfuscated/path` (system and
  default MongoDB paths are kept). Seeing these means the name was not
  discovered; the message around it is unchanged.
- Counts, durations and plans are unchanged, so findings about load, slow
  shapes, elections and connection churn hold for the original.

## Verify

`mongodb-log-obfuscator-go verify [--mapping FILE] OUTPUT_DIR` checks an
existing directory. It reports mapped originals still present, emails outside
`example.com`, public IPv4 addresses, card numbers (Luhn) and LDAP/X.509
names, plus mapping files inside the directory, with values masked
(`j…(17 chars)`; mapped originals are named by their replacement). A clean
result is evidence, not proof: a person's name in free text that was never
discovered is not detected, and field names are kept by design.

If the user gives known original identifiers (customer name, host names),
search the obfuscated output for them with `grep -n -F` and report hits by
file and line number only, without quoting the surrounding text. Then check
that the output is still usable: `mongodb-logstat --report queries CASE/obfuscated`
and `mongodb-ftdcstat CASE/obfuscated/<...>/diagnostic.data --view summary --avg 15m`.

## Changing the tool

Packages: `internal/inputs` (classification, skipped files, output paths),
`internal/discover` (finding names in logs and BSON), `internal/registry`
(categories, replacement forms, mapping), `internal/replace` (one-pass
replacement), `internal/redact` (payload rules, command allowlist, text
scrubbing, safety net, `--keep-equality`), `internal/processor` (pipeline,
FTDC and log writers, aggregation pipelines), `internal/pipeline` (parallel
blocks), `internal/logline` (prefixes, timestamps), `internal/timerange`,
`internal/verify`, `internal/ftdc`. Validate with `go test ./...` and
`go vet ./...`, build into a scratch path, and check that obfuscated samples
still read in `mongodb-logstat` and `mongodb-ftdcstat` and pass `verify`. Add a
test to `internal/processor/leaks_test.go` for every leak fixed. Update
`README.md` and this skill (the Codex copy under `skills/.codex/` has the same
body) when behaviour changes.
