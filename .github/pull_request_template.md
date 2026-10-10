## What

One or two sentences on what this changes.

## Why

The problem it solves. Link the issue (`Closes #123`) if there is one.

## How you verified it

Masker is a privacy tool: a subtle mistake leaks data, so say concretely what
you ran and what it showed. For example:

- `make check` (ruff, mypy strict, pytest with coverage)
- `bash examples/demo.sh` end to end
- a new test covering the specific path, and what it asserts
- against a real PostgreSQL/MySQL if the change touches dialect-specific code

## Checklist

- [ ] `make check` passes (lint, strict typecheck, tests, 85% coverage floor)
- [ ] New behaviour has tests, including the failure case it fixes
- [ ] `README.md` updated if a transformer, flag or rules-file key changed
- [ ] `CHANGELOG.md` entry added under *Unreleased*
- [ ] No secrets, keys or real personal data in tests, fixtures or examples
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)

## Notes for reviewers

Anything subtle, anything you were unsure about, anything deliberately left
out of scope.
