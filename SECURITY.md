# Security Policy

Masker exists to stop personal data leaking, so a vulnerability here is more
serious than a bug in most tools: the failure mode is that a masked database is
believed to be safe when it is not.

## Reporting a vulnerability

**Please do not open a public GitHub issue.**

Report privately through one of:

- GitHub Security Advisories: <https://github.com/zahidhasann88/masker/security/advisories/new>
- Email: jahidhasann67@gmail.com

Please include:

- the Masker version (`masker --version`) and Python version;
- the backend and version (SQLite / PostgreSQL / MySQL);
- a minimal `masker.yaml` and schema that reproduces it, with all secrets and
  real data removed;
- what you expected and what happened instead;
- whether you believe the issue is already public.

We aim to acknowledge reports within 3 working days and to give a substantive
response within 10. You will be credited in the release notes unless you ask
not to be.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | Yes — security fixes |
| < 0.1   | No |

Masker is pre-1.0. Minor releases may change the rules-file format; security
fixes are backported to the latest 0.1.x line.

## What counts as a security issue

Anything that would cause personal data to survive into the target, or that
would cause a user to believe it did not:

- a transformer that leaves an original value recoverable or unchanged;
- a rules-file construct that is silently ignored instead of rejected, so a
  column the user believed masked is copied verbatim;
- a `verify` or `scan` result that reports clean when it is not — a false
  negative is more serious than a false positive;
- credentials, keys or row values appearing in logs, error messages, reports or
  the rules file;
- a write reaching the source database;
- a foreign key silently pointing at the wrong row after masking.

## What is out of scope

These are documented limitations rather than vulnerabilities:

- Re-identification from combinations of unmasked columns. Masker reduces
  disclosure risk; it does not provide a legal guarantee of anonymity, and it
  does not claim to. See *Limitations* in the README.
- Free-text columns containing personal data. Column-wise masking cannot parse
  names or phone numbers out of prose; `scan` flags such columns instead.
- The strength of your key. A weak, shared or committed key is a deployment
  problem; Masker refuses keys under 12 characters and warns under 32, but it
  cannot protect a key you publish.
- Database server configuration, transport encryption or authentication.

## Security notes for users

- The masking key allows candidate source values to be tested against a masked dump. Treat it as
  a production secret: never in the rules file, never in version control, never
  in CI logs. Use `--ephemeral-key` for one-off copies.
- Keep the source read-only at the database level too (a dedicated read-only
  role), so a misconfiguration cannot become a write.
- Point `--target` at a database you would be comfortable sharing, because that
  is exactly what the output is for.
- Run `masker verify` in CI after every masked build, and `masker scan --strict`
  on schema changes. Both exit non-zero on a problem.
