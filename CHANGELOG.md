# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

First public release.

### Added

- **CLI** (`masker`) with the commands `init`, `scan`, `validate`, `run`,
  `verify`, `report` and `transformers`, plus the global flags `--verbose`,
  `--no-color`, `--key-file`, `--ephemeral-key` and `--version`.
- **Rules file** (`masker.yaml`) with per-table actions (`copy`, `skip`,
  `truncate`, `subset`), per-column transformer rules, and a `settings` block
  for batch size, NULL handling, schema creation, row caps, Faker locale,
  uniqueness retries and sample sizes. Unknown keys are rejected rather than
  ignored.
- **Thirteen transformers**: `fake`, `hash`, `partial_mask`, `redact`, `null`,
  `constant`, `shuffle`, `regex_replace`, `preserve_format`, `date_shift`,
  `number_noise`, `email` and `keep`, all registered by name and all
  deterministic under a shared key.
- **Determinism** from `HMAC-SHA256(secret_key, column_scope ‖ value)`, with
  per-column namespacing that is shared across both sides of a foreign key so
  joins survive masking.
- **Key management**: key from `MASKER_SECRET_KEY` or `--key-file`, never from
  the rules file; refusing to run without one; refusing keys shorter than 12
  characters; warning below 32; `--ephemeral-key` for throwaway output.
- **Uniqueness handling** with counter-salted retries and a clear error when the
  value space is too small.
- **Schema reflection** over SQLAlchemy Core for SQLite, PostgreSQL and
  MySQL/MariaDB, including primary keys, unique constraints (including SQLite
  inline `UNIQUE`, which is invisible to the usual inspector API), column
  lengths and nullability.
- **Foreign-key-aware ordering** using union-find grouping, with cycle detection
  and deferred constraint checks for tables that cannot be ordered.
- **`masker init`** generating a starter rules file covering every column, with
  PII suggestions marked `# SUGGESTED, review me`.
- **`masker scan`** combining column-name patterns with value sniffing on a
  sample of rows, listing columns with no rule, `--strict` as a CI gate, and
  `--json` output.
- **`masker run`** with batched streaming (default 5000 rows), one transaction
  per table, Rich progress, `--dry-run` with a partially hidden before/after
  sample, `--batch-size`, `--tables`, `--exclude`, `--subset-rows`,
  `--create-schema/--no-create-schema`, `--allow-non-empty` and `--yes`.
- **`masker verify`** sample-checking the target for surviving originals,
  reporting columns with no rule that look like PII, counting orphaned foreign
  keys, and distinguishing genuine leaks from the coincidences that
  domain-preserving transformers (`date_shift`, `number_noise`) legitimately
  produce.
- **`masker report`** rendering a run summary as Markdown or JSON, from the
  stats file a run writes.
- **Safety guards**: read-only source connections on all three backends,
  same-database refusal on normalized URLs, non-empty-target refusal, credential
  redaction in every URL and message, no row values in logs, and a per-run list
  of columns copied verbatim.
- **Test suite** covering every transformer, rules validation, PII heuristics,
  FK ordering, the safety guards and leak detection, plus an end-to-end SQLite
  integration test and opt-in PostgreSQL/MySQL integration tests.
- **Examples**: a sample schema, a sample `masker.yaml` and a 13-step SQLite
  demo script (`examples/demo.sh`).
- **Benchmark**: `scripts/bench_sqlite.py`, the source of the numbers in the
  README's Performance section.

[0.1.0]: https://github.com/zahidhasann88/masker/releases/tag/v0.1.0
