# Contributing to Masker

Thanks for considering it. Masker is a privacy tool, so the bar for correctness
is higher than usual: a transformer that is subtly wrong leaks data, and a
safety check that is subtly wrong is worse than no check at all. Please read
the notes below before opening a pull request.

## Getting set up

```bash
git clone https://github.com/zahidhasann88/masker && cd masker
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,postgres,mysql]'
pre-commit install
```

`make check` runs everything CI runs:

```bash
make check          # ruff + mypy (strict) + pytest with coverage
make lint           # ruff check
make format         # ruff format
make typecheck      # mypy --strict on src/
make test           # pytest
make demo           # end-to-end SQLite demo (examples/demo.sh)
make bench          # 100k-row benchmark
```

## Running the tests

The default suite runs everywhere — it needs no services, because the
integration tests use SQLite:

```bash
pytest
pytest --cov=masker --cov-report=term-missing
MASKER_RUN_PERF=1 pytest -m perf        # opt-in performance test
```

The PostgreSQL and MySQL suites are skipped unless you point them at a
disposable database. **They drop and recreate databases**, so never point them
at anything you care about.

```bash
export MASKER_TEST_POSTGRES_URL="postgresql+psycopg://postgres@localhost:5432/masker_test"
export MASKER_TEST_MYSQL_URL="mysql+pymysql://root@127.0.0.1:3306/masker_test"
pytest -m "postgres or mysql"
```

Both are exercised in CI against service containers.

## Code style

- Python 3.10+ syntax, `from __future__ import annotations` everywhere.
- `src/` layout; the package is `masker`.
- ruff (line length 100) and mypy in `strict` mode on `src/` must pass. The
  config lives in `pyproject.toml`; prefer fixing the code over adding an
  ignore, and if an ignore is genuinely needed, say why in a comment.
- Tests go in `tests/`, one module per source module where that mapping makes
  sense. Coverage floor is 85%.

## Commit messages and pull requests

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add a `tokenize` transformer for FPE-style masking
fix: stop `verify` flagging shifted dates as leaks
docs: document the cyclic foreign-key limitation
test: cover the unique-retry path for regex_replace
chore: bump ruff to 0.6
```

Keep one logical change per commit. In the PR description, say what the change
does, why, and — for anything touching masking or the safety guards — how you
verified it.

## How to add a transformer

A transformer is one module in `src/masker/transformers/`, registered by name.
The interface is deliberately small.

**1. Create the module.** For a transformer called `tokenize`:

```python
# src/masker/transformers/tokenize.py
"""``tokenize`` -- one-line description, plus a YAML example.

```yaml
columns:
  ssn: {transformer: tokenize, params: {prefix: "TKN"}}
```

Explain what it guarantees and what it does not. This docstring is the
documentation, so write it for someone deciding whether to trust it with a
column of personal data.
"""

from __future__ import annotations

from typing import Any

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register


class TokenizeParams(BaseParams):
    """Validated by pydantic; add constraints here rather than in `_apply`."""

    prefix: str = ""


@register
class TokenizeTransformer(BaseTransformer[TokenizeParams]):
    name = "tokenize"
    summary = "One-line summary shown by `masker transformers`."
    params_model = TokenizeParams

    # Declare the properties Masker needs to know about. Defaults are in
    # BaseTransformer; only override what differs.
    supports_uniqueness = True     # can produce distinct outputs per input?
    tracks_uniqueness = True       # should Masker enforce a UNIQUE constraint?
    value_scoped = True            # does output depend on the input value?
    requires_prepass = False       # does it need the whole column up front?
    preserves_domain = False       # can output land on another row's original?

    def _apply(self, value: Any, attempt: int) -> Any:
        # `value` is never None here unless null_passthrough is disabled;
        # use self.require_not_null(value) to get a clear error otherwise.
        # `attempt` is 0 on the first try and increments on a uniqueness retry,
        # so it must influence the output for retries to make progress.
        # Derive randomness from self.ctx.rng(...) or self.ctx.digest(...) --
        # never from the global random module, or determinism breaks.
        token = self.ctx.hex_digest(value, attempt, length=8)
        return f"{self.params.prefix}{token}"
```

**2. Export it.** Add the module to `src/masker/transformers/__init__.py` so
the `@register` decorator runs at import time.

**3. Test it.** `tests/test_transformers.py` has the patterns. At minimum cover:

- determinism: the same key and value produce the same output, twice;
- a different key produces a different output;
- NULL handling, both with `null_passthrough` on and off;
- length and type fitting into a narrow column;
- uniqueness: two distinct inputs give distinct outputs, and the retry path
  (`attempt > 0`) makes progress;
- anything specific to your guarantee (format preservation, bounds, locale).

**4. Document it.** Add a section to the transformer reference in `README.md`
with a YAML example, and a line to `CHANGELOG.md`.

**5. Consider `validate`.** If your transformer only makes sense for certain
column types — or can provably never satisfy a UNIQUE constraint — say so in
`masker/config.py` so the mistake is caught by `masker validate` instead of at
row 9,000,000.

### Rules for transformers

These are not style preferences; breaking them breaks guarantees users rely on.

1. **No unseeded randomness.** Everything random must come from
   `self.ctx.rng(...)` or `self.ctx.digest(...)`, both derived from the key and
   the value. Output must be reproducible.
2. **Never log or raise with the original value.** Errors name the column, not
   the data. `MaskerError` messages are printed to the console.
3. **Output must fit the column.** Return something `fit_value` can coerce; if
   your transformer produces strings, they will be truncated to the column
   length, so prefer generating at the right length.
4. **`attempt` must change the output** if the transformer claims
   `supports_uniqueness`, otherwise a uniqueness retry loops forever.
5. **Set `preserves_domain = True` only if it is true** — that is, if a masked
   value can legitimately equal another row's original. It controls whether
   `verify` reports a match as a warning or as a leak, so getting it wrong
   either hides a leak or cries wolf.

## Reporting issues

Use the issue templates. For anything that looks like a security problem, see
[SECURITY.md](SECURITY.md) instead — please do not open a public issue.

A useful bug report includes the Masker version (`masker --version`), the
Python version, the backend, a `masker.yaml` with the secrets removed, and the
redacted error output.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
