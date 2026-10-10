# Masker

Masker copies database rows into a separate target and applies deterministic masking rules to selected columns.

It supports SQLite, PostgreSQL and MySQL through SQLAlchemy Core. Review the rules, inspect a dry-run, and verify the copy before sharing it. Masking and sample checks reduce disclosure risk; they do not prove that a database is anonymous.

The CLI and Python import package are `masker`. The PyPI distribution is **`masker-db`** because the name `masker` belongs to another project. Until the first PyPI release, install from this checkout or a wheel attached to a GitHub release.

---

## The problem

Everyone needs production-shaped data and nobody is allowed to have it:

- **Test and staging environments** get stale, hand-made fixtures that don't match reality, so bugs only appear in production.
- **Support and analytics** need to query real data, which means real personal data sits on laptops and in third-party tools.
- **Demos** get run against production because building a realistic dataset takes longer than the demo.
- The usual workaround — someone dumping the database and hand-editing a few columns — misses the column nobody remembered, and there is no way to prove afterwards that it didn't.

Masker combines reviewed rules, deterministic transforms and sample-based verification.

## Masker vs. a synthetic-data generator

These are different tools for different problems. Masker is **not** a synthetic-data generator.

| | **Masker** | Synthetic-data generator |
|---|---|---|
| Where the data comes from | Your real rows | Nothing — invented from scratch |
| Referential integrity | Preserved when FK rules, types and selected rows are compatible | Must be modelled and generated |
| Distributions, skew, dirty edges | Depends on the transformer and its settings | Only as good as the model you specify |
| Row-for-row traceability | Yes: same row in, same row out | No |
| Reproduces an existing bug | Yes | Unlikely |
| Useful when you have no production data yet | No | Yes |

If you need data that has never existed, use a generator. If you need *this* database with the identifying parts removed, use Masker.

---

## Install

Masker needs Python 3.10 or newer.

```bash
# pipx (recommended for a CLI you just want to use)
pipx install masker-db  # after the first PyPI release

# uv
uv tool install masker-db

# pip, into the current environment
pip install masker-db
```

Database drivers are extras — install the one for your **source** database. SQLite needs nothing.

```bash
pip install 'masker-db[postgres]'   # PostgreSQL  (psycopg 3)
pip install 'masker-db[mysql]'      # MySQL / MariaDB (PyMySQL)
pip install 'masker-db[postgres,mysql]'
```

---

## Quickstart

![Masker dry-run preview showing masking rules and redacted before-and-after values](docs/screenshots/demo.png)

Dry-run preview using synthetic demo data. Preview values are redacted.

### 1. Generate a rules file from your schema

```bash
masker init --source "postgresql://user@localhost:5432/app" --output masker.yaml
```

`init` reflects the schema and writes a rule for **every column of every table**. Columns that look like personal data get a suggested transformer marked so you cannot miss them:

```yaml
  customers:
    action: copy
    columns:
      email:
        # SUGGESTED, review me: matches PII pattern 'email'
        transformer: email
        params:
          domain: example.test
      full_name:
        # SUGGESTED, review me: matches PII pattern 'person'
        transformer: fake
        params:
          provider: name
      created_at:            # nothing detected -- copied verbatim
        transformer: keep
```

Nothing is masked until you review this file. That is deliberate: a generated suggestion is a starting point, not a decision.

### 2. Check what is still exposed

```bash
masker scan --source "$PROD_URL" --rules masker.yaml --strict
```

`scan` combines column-name patterns with value sniffing on a sample of rows (it will notice a column of emails called `ref_1`), lists every column that has **no rule at all**, and with `--strict` exits 1 if any suspected PII column is unmasked. Wire it into CI and it becomes a guard rail: the build fails when someone adds a `phone_number` column without a rule.

### 3. Set a key, validate, then dry-run

```bash
export MASKER_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
masker validate --rules masker.yaml --source "$PROD_URL"
masker run --source "$PROD_URL" --target "$STAGING_URL" --rules masker.yaml --dry-run
```

`validate` checks the rules against the real schema: unknown tables or columns, transformers that cannot fit the column type, a `hash` longer than the column, transformers that cannot satisfy a UNIQUE constraint, and foreign keys masked on one side only. `--dry-run` prints the plan plus a before/after sample with the originals partially hidden, and writes nothing.

### 4. Run, then check the copy

```bash
masker run    --source "$PROD_URL" --target "$STAGING_URL" --rules masker.yaml
masker verify --source "$PROD_URL" --target "$STAGING_URL" --rules masker.yaml
```

`verify` samples the target and looks for original values that survived, reports columns with no rule that look like PII, and counts orphaned foreign keys. It exits 1 if it finds anything.

### 5. Report

```bash
masker report --format markdown          # or: --format json
```

---

## The rules file

```yaml
version: 1

settings:
  batch_size: 5000          # rows per insert batch
  null_passthrough: true    # NULL in, NULL out (default true)
  create_schema: true       # create missing tables in the target
  subset_rows: null         # global cap: copy at most N rows per table
  locale: null              # Faker locale for `fake` (e.g. "de_DE")
  unique_max_attempts: 1000 # retries before giving up on a UNIQUE column
  sample_size: 200          # rows sniffed per column by `scan`
  verify_sample_size: 500   # values checked per column by `verify`

tables:
  customers:
    action: copy            # copy | skip | truncate | subset
    subset_rows: 10000      # only used with action: subset (or settings.subset_rows)
    order_by: [id]          # deterministic ordering for subsets
    columns:
      id:            {transformer: hash}
      email:         {transformer: email}
      full_name:     {transformer: fake, params: {provider: name}}
      phone:         {transformer: partial_mask, params: {keep_last: 4}}
      date_of_birth: {transformer: date_shift, params: {min_days: -30, max_days: 30}}
      lifetime_value: {transformer: number_noise, params: {percent: 10, round_to: 2}}
      notes:         {transformer: redact}
      created_at:    {transformer: keep}     # an explicit decision, not an omission

  orders:
    action: copy
    columns:
      id:          {transformer: hash}
      customer_id: {transformer: hash}       # must match customers.id -- Masker checks this
      total:       {transformer: number_noise, params: {percent: 5, round_to: 2}}

  audit_log:
    action: skip            # not copied at all
```

Per-table actions:

| Action | Effect |
|---|---|
| `copy` | Copy every row, applying the column rules (default) |
| `skip` | Do not create or copy the table |
| `truncate` | Create the table, copy no rows |
| `subset` | Copy at most `subset_rows` rows, ordered by `order_by` |

Any unknown key in the file is an error rather than a silent ignore.

---

## Transformer reference

Every transformer is deterministic: the same key, the same source value and the same column always produce the same output. Run `masker transformers` for a live listing.

### `fake` — realistic replacement values
Uses a named [Faker](https://faker.readthedocs.io/) provider, seeded from the key and the original value, so the same input always maps to the same fake.

```yaml
full_name:      {transformer: fake, params: {provider: name}}
street_address: {transformer: fake, params: {provider: street_address}}
city:           {transformer: fake, params: {provider: city, locale: de_DE}}
```
Params: `provider` (required), `locale`, `args`, `kwargs`. Output is truncated to fit the column.

### `hash` — keyed digest
HMAC-SHA256 of the value. Hex for text columns, an integer for integer columns, so primary and foreign keys keep their type and stay joinable.

```yaml
id:      {transformer: hash}
ssn:     {transformer: hash, params: {length: 11}}
ref:     {transformer: hash, params: {length: 8, prefix: "R-", uppercase: true}}
```
Params: `length` (default 12), `prefix`, `uppercase`, `as_number` (auto-detected from the column type).

### `partial_mask` — keep part of it
```yaml
phone:       {transformer: partial_mask, params: {keep_last: 4}}
credit_card: {transformer: partial_mask, params: {keep_last: 4, mask_char: "•"}}
```
`"4111111111111111"` → `"************1111"`. Params: `keep_first` (0), `keep_last` (4), `mask_char` (`*`).

### `redact` — one marker for everything
```yaml
notes:         {transformer: redact}
medical_notes: {transformer: redact, params: {value: "[WITHHELD]"}}
```
Cannot satisfy a UNIQUE column, and Masker refuses to run rather than produce duplicates.

### `null` — drop the column's contents
```yaml
password_hash: {transformer: null}
```

### `constant` — one fixed value
```yaml
country: {transformer: constant, params: {value: "XX"}}
```

### `keep` — copy unchanged, on purpose
```yaml
created_at: {transformer: keep}
```
`keep` is not the same as "no rule". A `keep` is a reviewed decision and is never reported as unmasked PII; a missing rule is reported, and `verify` fails on it if the column looks like PII.

### `shuffle` — permute the column's own values
```yaml
salary: {transformer: shuffle}
```
Distinct values are permuted with no fixed points. With duplicates, frequencies can move between values, so the full distribution is not necessarily preserved. A single distinct value cannot be shuffled and is rejected. Shuffle keeps the original value set in the database: do not use it to remove identifying values; `verify` will flag those matches. It holds distinct values in memory and does not preserve joins across independently shuffled columns.

### `regex_replace` — surgical rewrites
```yaml
url:      {transformer: regex_replace, params: {pattern: "https?://[^/]+", replacement: "https://example.test"}}
ref_code: {transformer: regex_replace, params: {pattern: "\\d", replacement: "X"}}
```
Params: `pattern` (required), `replacement` (required), `count` (0 = all), `ignore_case`.

### `preserve_format` — same shape, different content
Keeps the length and the character class of every position: digits stay digits, letters stay letters, separators stay put.

```yaml
postcode:   {transformer: preserve_format}
ip_address: {transformer: preserve_format, params: {keep_positions: 3}}
```
`"555-0142"` → `"569-8342"`; `"192.168.1.42"` with `keep_positions: 3` → `"192.168.1.77"`.

### `date_shift` — move dates by a bounded offset
```yaml
date_of_birth: {transformer: date_shift, params: {min_days: -30, max_days: 30}}
signed_up_at:  {transformer: date_shift, params: {min_days: -365, max_days: 0, clamp_min: "2020-01-01"}}
```
Params: `min_days` (−365), `max_days` (365), `min_seconds`, `max_seconds`, `clamp_min`, `clamp_max`. Each value receives its own offset; date ordering and intervals are not guaranteed to survive.

### `number_noise` — jitter numbers
```yaml
salary:         {transformer: number_noise, params: {percent: 10}}
lifetime_value: {transformer: number_noise, params: {percent: 10, round_to: 2}}
lat:            {transformer: number_noise, params: {min_delta: -0.01, max_delta: 0.01}}
```
Params: `percent`, `min_delta`, `max_delta`, `round_to`. Bounded noise changes values but may leave some unchanged, especially after rounding. It is not encryption and does not guarantee that individual values cannot be inferred.

### `email` — same structure, safe domain
```yaml
email:      {transformer: email}
work_email: {transformer: email, params: {domain: example.test, style: hash}}
```
`"jane.doe+news@corp.example"` → `"bravo.foxtrot48213579+echo@example.test"`. The dot and `+tag` structure survives; the domain is replaced by a reserved, unroutable one so nothing can ever receive mail from a masked dump. Params: `domain`, `style` (`words` | `hash`), `suffix_digits` (8), `keep_domain` (false — a real domain in a shared dump is itself a disclosure).

---

## Determinism and key management

Masking is deterministic: the output for a value is

```
HMAC-SHA256(secret_key, column_scope ‖ original_value)
```

The same key, rules, source snapshot, dependency versions and traversal order produce repeatable row values. This does not promise byte-identical database files. Uniqueness collision resolution depends on the values processed before it. Because the digest is namespaced per column — and shared across both sides of a foreign key — `orders.customer_id` still joins to `customers.id` after masking.

**The key comes from the environment, never from the rules file:**

```bash
export MASKER_SECRET_KEY="..."        # or
masker --key-file /run/secrets/masker.key run ...
```

Masker refuses to run without a key. There is no default and no value in `masker.yaml` that would act as one, because a key committed to a repository is not a key.

> ### Protect the key
>
> Anyone holding the key can test candidate source values against deterministic outputs. This makes low-entropy values vulnerable to guessing. Store the key where you store other production secrets, rotate it deliberately, and never put it in the rules file, the CI logs or the database you are shipping.
>
> If you want a one-off copy you will never regenerate, use `--ephemeral-key`: it generates a throwaway key, prints a warning that the output is not reproducible, and does not persist anything.

Keys shorter than 12 characters are refused outright, and anything under 32 characters produces a warning.

### Uniqueness

When a column has a UNIQUE or primary-key constraint, Masker retries with a counter salt until it finds an unused value, and gives a clear error if the value space is too small (for example `hash` with `length: 1` on a 100k-row column) instead of writing duplicates.

---

## Safety guarantees

These are enforced in code, not just documented:

- **File-based sources are opened read-only.** SQLite is opened with `mode=ro`; PostgreSQL connections set `default_transaction_read_only`; MySQL/MariaDB sessions run `SET SESSION TRANSACTION READ ONLY`. An accidental write attempt fails at the driver level.
- **Source and target may not be the same database.** URLs are normalized (credentials and driver variants ignored, default ports resolved, SQLite paths resolved) and compared before anything is written. Private in-memory SQLite engines are separate databases. Named URI memory databases are not supported. DNS aliases and server redirects may evade URL identity checks; use a read-only source role and clearly separate targets.
- **A non-empty target is refused** unless you pass `--allow-non-empty`. With that flag, Masker deletes the rows of the tables it is about to write — children before parents — so a refresh is idempotent instead of colliding with the rows already there.
- **Connection secrets are redacted from normal output.** Passwords are stripped from every URL and message Masker prints, `password=`-style pairs are scrubbed from error text, and key material is omitted from its object representation. Database insert error details are withheld because servers can include row values. Row values are never logged at INFO.
- **Every run lists what it did not mask.** The summary names the columns copied verbatim, so "we masked everything" is checkable rather than assumed.
- **Target data is not written without a key**, and `--dry-run` does not open or modify the target.

---

## Performance

Measured with `scripts/bench_sqlite.py` on a container with 2 vCPU (Intel Xeon @ 2.60 GHz), 1 GB RAM, Linux 6.1, Python 3.13.16, SQLite, no tuning:

| Rows | Masked columns | Time | Throughput |
|---|---|---|---|
| 200,000 (100k customers + 100k orders) | 13 | 36.2 s | ~5,500 rows/s |

Per-transformer cost, same machine (µs per value):

| Transformer | µs/value |
|---|---|
| `redact`, `keep` | 0.7 |
| `partial_mask` | 1.2 |
| `hash` | 5.4 |
| `number_noise`, `date_shift` | 16–18 |
| `email` | 17.6 |
| `fake` | 80–100 |

Read this honestly:

- **`fake` dominates.** It calls Faker once per value and is roughly 15× slower than `hash`. A table with two `fake` columns spends most of its time there. Prefer `hash`, `partial_mask` or `preserve_format` on very large tables where realism does not matter.
- **Batch size barely matters.** 100k rows took 17.1 s at `batch_size: 1000`, 17.8 s at 5000 and 17.3 s at 20000. The default 5000 is fine.
- **These are SQLite-on-local-disk numbers**, i.e. the best case. A networked PostgreSQL or MySQL adds round-trip latency, so expect less. Rows are streamed in batches, but unique-output sets, resolved FK mappings and shuffle pre-passes grow with distinct-value counts.
- Numbers are for orientation, not a promise. Run `scripts/bench_sqlite.py --rows 250000` on your own hardware.

---

## Limitations

Read these before you rely on the output.

**Cyclic foreign keys.** SQLite and PostgreSQL copy cyclic groups in one transaction with deferred constraints. Newly created PostgreSQL cyclic FKs are marked deferrable; pre-existing target constraints must already support deferral. MySQL cycles are refused before schema creation rather than disabling FK checks. Refreshes clear in-scope tables in a separate transaction; a later copy failure does not restore their previous contents.

**Cross-dialect copies.** The target schema is created from the reflected source schema. Schema reflection does not copy every backend object (such as grants, triggers or stored procedures); copying SQLite → PostgreSQL is best effort and unusual types may need attention.

**Free text needs an explicit rule.** A `notes` or `bio` column containing "call Jane on 555-0142" is one opaque string to a column-wise masker. `scan` flags such columns, `redact` or `null` are the honest options, and no transformer here parses names out of prose.

**Values that identify people in combinations.** Masking each column independently does not prevent re-identification from a rare combination of what remains — `date_of_birth` + `postcode` + `gender` is the classic example. `date_shift` and `number_noise` exist to blunt this, and `scan --strict` exists to make you look at what is left.

**Re-identification is not a legal question this tool answers.** Masker reduces disclosure risk; it does not make data anonymous in the sense of GDPR or any other regime, and nothing here is legal advice. If you are relying on this for a compliance obligation, get it reviewed by someone qualified.

**No incremental runs.** A run copies the tables you select. There is no change tracking, so refreshing a large database means re-running it.

---

## Design decisions

Choices made while building this, so you can disagree with them knowingly:

- **Deterministic by default, keyed by HMAC.** Reproducibility is worth more than per-run randomness for test data: you can diff two runs and refresh one table. Random-per-run output is available via `--ephemeral-key`.
- **NULL in, NULL out** (`null_passthrough: true`). NULL usually means "unknown", and inventing a value would create information that was never there. Set it to `false` to mask NULLs too.
- **Output is fitted to the supported column types.** Masked values are truncated or coerced to the target column's type and length rather than aborting the run, because one over-long fake name should not cost you a 10-million-row copy.
- **`keep` is distinct from "no rule".** An explicit `keep` is a decision and is never flagged; a missing rule is flagged and fails `scan --strict` / `verify`.
- **`verify` classifies overlaps by transformer.** `date_shift` and `number_noise` stay inside the original value domain, so a shifted date can legitimately equal another row's original date. A handful of such matches is reported as a warning; a column where at least half the sampled values match is reported as an error, because that means the transform did nothing.
- **The rules file is the only configuration that travels.** Settings can be overridden on the command line, but a run is fully described by `masker.yaml` plus the key.

---

## Development

```bash
git clone https://github.com/zahidhasann88/masker && cd masker
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,postgres,mysql]'
pre-commit install

make lint typecheck test       # or: make check
make demo                      # end-to-end SQLite demo
```

`make check` runs ruff, mypy (strict, on `src/`) and pytest with an 85% coverage floor — the same checks CI runs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution guide, including how to add a transformer.

## Roadmap

- Incremental / changed-row-only runs
- Differential-privacy-style generalization (bucketing, k-anonymity reports)
- Column statistics report (before/after distribution comparison)
- Parallel per-table workers
- More backends: SQL Server, Oracle
- `masker diff` to compare two masked runs

## Licence

MIT — see [LICENSE](LICENSE).

## Security

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

### Windows development

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,postgres,mysql]"
.\.venv\Scripts\python.exe -m ruff check src tests scripts examples
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m pytest --cov=masker
.\.venv\Scripts\python.exe examples/demo.py
```

For releases, build with `python -m build`. GitHub tags create wheel and source archives. PyPI publishing is enabled only after a trusted publisher is configured and the repository variable `PUBLISH_TO_PYPI` is set to `true`.
