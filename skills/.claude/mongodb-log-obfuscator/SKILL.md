---
name: mongodb-log-obfuscator
description: Obfuscate customer MongoDB logs and FTDC diagnostic data before an agent reads them, with mongodb-log-obfuscator-go, and check the result. Use before analysing logs or diagnostic.data from a customer case with an agent, or when the user asks to obfuscate, sanitize, anonymize or redact MongoDB logs/FTDC, to check obfuscated output for leaks, or to explain the obfuscator's output, mapping or exit status. Not for analysing the logs (use mongodb-logstat and mongodb-ftdcstat on the obfuscated output) or for other databases.
---

# mongodb-log-obfuscator

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

   Several inputs (files and directories) share one mapping:
   `mongodb-log-obfuscator-go --verify --out CASE/obfuscated CASE/node1.log CASE/node2/diagnostic.data`.
   Add `--keep-equality` when equal values must stay recognisable (hot keys,
   skewed filters, the same document updated repeatedly).
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
