# Changelog

All notable changes are listed here. Versions follow
[semantic versioning](https://semver.org/); see "Versions and releases" in the
README.

## Unreleased

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
