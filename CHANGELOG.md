# Changelog

All notable changes are listed here. Versions follow
[semantic versioning](https://semver.org/); see "Versions and releases" in the
README.

## Unreleased

## v0.1.1 - 2026-11-09

- Database and collection names used as keys are mapped: documents that
  describe the catalog (`{"<db>": {"collections": {"<coll>": ...}}}`), and
  `<db>.<collection>` keys. Before, an application document storing the
  catalog kept the real names in its keys, inside redacted payloads too.
- Path keys also map user, database and collection names: an FTDC mount such
  as `/run/user/<uid>` kept the user name.
- `verify` reports those names in keys, and masks originals in the key path
  it prints.
- Tests guard that MongoDB query hashes (`queryHash`, `planCacheKey`, ...)
  keep their original values.

## v0.1.0 - 2026-11-06

First versioned release.

- Obfuscates MongoDB logs (structured JSON, with syslog/kubectl/docker
  prefixes, plain or gzip) and FTDC with one shared mapping: hosts keep their
  site structure, IPs their subnet, internal and tool names are kept.
- Redacts user data while keeping query shape: command payloads, an
  allowlist for other command strings, replicated operations, duplicate-key
  values, change-stream images, card numbers in text, LDAP and X.509 names;
  aggregation pipelines keep their structure outside `$match`.
- `--verify` and `verify OUTPUT_DIR`: masked report of mapped originals,
  emails, public IPs, card numbers and LDAP names left in the output.
- `--keep-equality`: keyed hashes so repeated values stay visible.
- The mapping is written next to the output directory with mode 0600.
- Files recognised by content; archives, binaries and empty files listed as
  skipped; a failed file does not stop the others.
- `--jobs` workers process files and blocks of large files in parallel.
- `--version`; the version is saved in the mapping.
- `--from`/`--to`: keep only the log lines and FTDC chunks of a time window.
- Safety net: host names, IPs, emails and customer paths the mapping missed
  are replaced in text after the mapping.
- Claude and Codex skills (`skills/.claude/mongodb-log-obfuscator-go`,
  `skills/.codex/mongodb-log-obfuscator-go`).
