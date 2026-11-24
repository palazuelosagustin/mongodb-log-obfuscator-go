# Changelog

All notable changes are listed here. Versions follow
[semantic versioning](https://semver.org/); see "Versions and releases" in the
README.

## Unreleased

## v0.2.0 - 2026-11-24

- Organization names that differ only in case ("Cisco" from a certificate,
  "cisco" from an LDAP `dc=`) get one `OrganizationN`; the label matches
  both in any case. Public certificate authorities (IdenTrust, DigiCert,
  Let's Encrypt, Sectigo…) are not taken as organization names. WiredTiger
  idents such as `table:<db>/index-12-345` are not taken as index names:
  their database is mapped and the rest kept.

- Command oplog entries (`op: "c"`) are handled like commands: their
  collection and index names are mapped, and key patterns and UUIDs kept.
  Before, `o` was redacted like a user document, so a replicated
  `createIndexes` or `startIndexBuild` lost its collection, index name,
  key pattern and build UUID. Filters, validators, view pipelines and the
  documents inside `applyOps` are still redacted.

- Index names are mapped whole to `indexN` wherever they appear (index
  fields, index specs, `indexesBuilt`, `hint`, E11000 and index error
  messages). Names such as `uq_<collection>_date` kept collection names and
  business terms. `_id_` stays; `planSummary` keeps its key pattern even when
  an index is named after a field; `verify` reports index names left.

- UUIDs are kept whole. About 1 in 10,000 had all-digit groups that passed
  the card-number check and were partly rewritten to `obfuscated-number`,
  which broke correlation by connection, collection or index build UUID.
  `verify` no longer reports such a UUID as a card number.

- Application names in client metadata (`doc.application.name`) are mapped
  to `appN`. Before, a name was only mapped when it also appeared as
  `appName` in a slow query, so clients whose operations were never slow,
  such as monitoring agents, kept their real names.

- The organization name of each customer domain (`acme` of `db1.acme.com`)
  joins the `org` category and is replaced wherever it appears, in any case
  and next to digits, `_` or `-`: an agent or job name such as
  `agent-acme1-prod` inside an error message no longer keeps it.
  Platform suffixes, vendor names and generic words are not taken. Org names
  of 4 or more letters from LDAP names match the same way.
- The run summary prints how many organization names came from domains.
- `verify` searches organization names the same way.

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
