"""The ``masker`` command line interface.

Every command follows the same shape: resolve the key if it needs one, do the
work in a library module, render the result with Rich, and translate
:class:`~masker.errors.MaskerError` into a redacted message on stderr plus a
non-zero exit code.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from sqlalchemy.exc import SQLAlchemyError

from masker import __version__
from masker.config import Issue, compile_rules, load_rules, validate_rules
from masker.connect import redact_text, redact_url, source_engine
from masker.console import error_console, get_console, set_color_enabled
from masker.console import table as rich_table
from masker.engine import DryRunPlan, MaskingEngine, RunOptions, RunResult
from masker.errors import ConfigError, KeyError_, MaskerError
from masker.init import render_starter_rules
from masker.keys import EPHEMERAL_WARNING, SECRET_KEY_ENV, SecretKey
from masker.report import DEFAULT_STATS_FILE, load_stats, save_stats, write_report
from masker.scan import ScanResult, scan_schema
from masker.schema import ReflectedSchema, reflect_schema
from masker.transformers.registry import REGISTRY
from masker.verify import VerifyResult
from masker.verify import verify as verify_target

__all__ = ["app", "main"]

app = typer.Typer(
    name="masker",
    help="Copy a database into a separate target with reviewed masking rules.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

EXIT_OK = 0
EXIT_FAILURE = 1


@dataclass(slots=True)
class CliState:
    """Global flags shared by every command."""

    verbose: bool = False
    key_file: str | None = None
    ephemeral: bool = False


def _version_callback(value: bool) -> None:
    if value:
        get_console().print(f"masker {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def _root(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug level detail."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colour output."),
    key_file: str | None = typer.Option(
        None, "--key-file", help="File holding the masking key (overrides $MASKER_KEY_FILE)."
    ),
    ephemeral_key: bool = typer.Option(
        False,
        "--ephemeral-key",
        help="Generate a throwaway key. Output will NOT be reproducible.",
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show the version."
    ),
) -> None:
    """Copy a database into a separate target with reviewed masking rules."""
    set_color_enabled(not no_color)
    ctx.obj = CliState(verbose=verbose, key_file=key_file, ephemeral=ephemeral_key)
    if ephemeral_key:
        error_console().print(
            f"[warn]warning:[/warn] {EPHEMERAL_WARNING.format(key_env=SECRET_KEY_ENV)}"
        )


# --------------------------------------------------------------------------- #
# Shared plumbing
# --------------------------------------------------------------------------- #
def _state(ctx: typer.Context) -> CliState:
    state = ctx.obj
    return state if isinstance(state, CliState) else CliState()


def _resolve_key(ctx: typer.Context, *, required: bool) -> SecretKey | None:
    state = _state(ctx)
    try:
        return SecretKey.resolve(key_file=state.key_file, ephemeral=state.ephemeral)
    except KeyError_ as exc:
        if required:
            _fail(exc)
        return None


def _fail(error: MaskerError, code: int = EXIT_FAILURE) -> None:
    """Print a redacted error and exit."""
    console = error_console()
    console.print(f"[err]{type(error).__name__}:[/err] {redact_text(error.message)}")
    if error.hint:
        console.print(f"  [dim]hint:[/dim] {redact_text(error.hint)}")
    raise typer.Exit(code)


def _guard(action: Any) -> Any:
    """Run ``action``, translating Masker errors into a clean exit."""
    try:
        return action()
    except MaskerError as exc:
        _fail(exc)
        return None  # pragma: no cover - _fail always raises
    except (SQLAlchemyError, OSError, ValueError) as exc:
        _fail(
            MaskerError(
                f"{type(exc).__name__}: the operation failed. Check the database connection, "
                "file permissions and transformer settings."
            )
        )
    except typer.Exit:
        raise
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        error_console().print("[warn]Interrupted.[/warn]")
        raise typer.Exit(130) from None


def _select(
    tables: Sequence[str] | None,
    exclude: Sequence[str] | None,
    schema: ReflectedSchema,
) -> list[str] | None:
    names = set(schema.tables)
    unknown = (set(tables or ()) | set(exclude or ())) - names
    if unknown:
        raise ConfigError(f"Unknown table(s): {', '.join(sorted(unknown))}")
    if not tables and not exclude:
        return None
    return sorted((set(tables) if tables else names) - set(exclude or ()))


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
@app.command()
def init(
    ctx: typer.Context,
    source: str = typer.Option(..., "--source", help="SQLAlchemy URL of the database to read."),
    output: Path = typer.Option(
        "masker.yaml", "--output", "-o", help="Where to write the rules file."
    ),
    tables: list[str] | None = typer.Option(None, "--tables", help="Only include these."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Skip these."),
    sample_size: int = typer.Option(
        200, "--sample-size", min=1, help="Rows sniffed per column for value patterns."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Reflect the schema and write a starter masker.yaml."""

    def action() -> None:
        if output.exists() and not force:
            raise ConfigError(f"{output} already exists.", hint="Pass --force to overwrite it.")
        with source_engine(source) as engine:
            schema = reflect_schema(engine)
            wanted = _select(tables, exclude, schema)
            findings = scan_schema(engine, schema, sample_size=sample_size, tables=wanted)
            text = render_starter_rules(schema, findings, source_url=source, tables=wanted)

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")

        suggested = sum(1 for finding in findings.findings if finding.transformer != "keep")
        console = get_console()
        console.print(f"[ok]Wrote[/ok] {output}")
        console.print(
            f"  {findings.tables_scanned} table(s), {findings.columns_scanned} column(s), "
            f"{suggested} suggested rule(s)."
        )
        console.print("  [warn]Review every '# SUGGESTED, review me' rule before running.[/warn]")

    _guard(action)


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    ctx: typer.Context,
    source: str = typer.Option(..., "--source", help="SQLAlchemy URL of the database to read."),
    rules: Path | None = typer.Option(
        None, "--rules", help="Rules file to compare against (finds unmasked columns)."
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Exit 1 if any suspected PII column is unmasked."
    ),
    tables: list[str] | None = typer.Option(None, "--tables", help="Only scan these."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Skip these."),
    sample_size: int = typer.Option(200, "--sample-size", min=1, help="Rows sniffed per column."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of tables."),
) -> None:
    """Report columns that look like PII, and columns with no rule."""

    def action() -> None:
        loaded = load_rules(rules) if rules else None
        with source_engine(source) as engine:
            schema = reflect_schema(engine)
            result = scan_schema(
                engine,
                schema,
                loaded,
                sample_size=sample_size,
                tables=_select(tables, exclude, schema),
            )
        if as_json:
            get_console().print_json(json.dumps(result.to_dict()))
        else:
            _print_scan(result)
        if strict and not result.ok:
            raise typer.Exit(EXIT_FAILURE)

    _guard(action)


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #
@app.command()
def validate(
    ctx: typer.Context,
    rules: Path = typer.Option("masker.yaml", "--rules", help="Path to the rules file."),
    source: str = typer.Option(..., "--source", help="SQLAlchemy URL to validate against."),
    strict: bool = typer.Option(False, "--strict", help="Exit 1 on warnings as well as errors."),
) -> None:
    """Check the rules against the schema before running anything."""

    def action() -> None:
        loaded = load_rules(rules)
        with source_engine(source) as engine:
            schema = reflect_schema(engine)
        issues = validate_rules(loaded, schema)

        key = _resolve_key(ctx, required=False)
        if key is None:
            issues.append(
                Issue(
                    "error",
                    "missing-key",
                    "No masking key available.",
                    hint=(
                        f"Set {SECRET_KEY_ENV}, point --key-file at a key file, or use "
                        "--ephemeral-key."
                    ),
                )
            )
        else:
            try:
                compile_rules(loaded, schema, key)
            except MaskerError as exc:
                issues.append(Issue("error", "unusable-rule", exc.message, hint=exc.hint))

        _print_issues(issues)
        errors = [issue for issue in issues if issue.severity == "error"]
        warnings = [issue for issue in issues if issue.severity == "warning"]
        if errors or (strict and warnings):
            raise typer.Exit(EXIT_FAILURE)

    _guard(action)


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
@app.command()
def run(
    ctx: typer.Context,
    source: str = typer.Option(..., "--source", help="SQLAlchemy URL of the database to read."),
    target: str = typer.Option(..., "--target", help="SQLAlchemy URL of the database to write."),
    rules: Path = typer.Option("masker.yaml", "--rules", help="Path to the rules file."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the plan and a masked sample; write nothing."
    ),
    batch_size: int | None = typer.Option(
        None, "--batch-size", min=1, help="Rows per insert batch (default: settings.batch_size)."
    ),
    tables: list[str] | None = typer.Option(None, "--tables", help="Only copy these."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Skip these."),
    subset_rows: int | None = typer.Option(
        None, "--subset-rows", min=1, help="Copy at most N rows per table."
    ),
    create_schema: bool | None = typer.Option(
        None, "--create-schema/--no-create-schema", help="Create missing tables in the target."
    ),
    allow_non_empty: bool = typer.Option(
        False, "--allow-non-empty", help="Write into a target that already has data."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
    stats_file: Path | None = typer.Option(
        Path(DEFAULT_STATS_FILE), "--stats-file", help="Where to write the run summary JSON."
    ),
    sample_rows: int = typer.Option(
        5, "--sample-rows", min=0, help="Rows shown per table by --dry-run."
    ),
) -> None:
    """Copy the schema and masked data into the target database."""

    def action() -> None:
        key = _resolve_key(ctx, required=True)
        assert key is not None  # _resolve_key exits when required and missing
        loaded = load_rules(rules)
        # Command-line options win over the rules file, but only when given:
        # clobbering settings with the CLI defaults would silently ignore a
        # batch_size or subset_rows set in masker.yaml.
        overrides: dict[str, Any] = {}
        if batch_size is not None:
            overrides["batch_size"] = batch_size
        if subset_rows is not None:
            overrides["subset_rows"] = subset_rows
        if overrides:
            loaded.settings = loaded.settings.model_copy(update=overrides)
        options = RunOptions(
            batch_size=loaded.settings.batch_size,
            only=list(tables) if tables else None,
            exclude=list(exclude) if exclude else None,
            subset_rows=subset_rows,
            create_schema=(
                loaded.settings.create_schema if create_schema is None else create_schema
            ),
            allow_non_empty=allow_non_empty,
            sample_rows=sample_rows,
        )
        engine = MaskingEngine(
            source_url=source, target_url=target, rules=loaded, key=key, options=options
        )

        if dry_run:
            _print_dry_run(engine.dry_run())
            return

        needs_confirmation = not yes and sys.stdin.isatty()
        if needs_confirmation and not typer.confirm(
            f"Write masked data to {redact_url(target)}?", default=False
        ):
            raise typer.Exit(EXIT_OK)

        progress = _RichProgress() if get_console().is_terminal else None
        engine.progress = progress
        try:
            result = engine.run()
        finally:
            if progress is not None:
                progress.stop()

        _print_run(result)
        if stats_file is not None:
            get_console().print(
                f"[dim]Run summary written to {save_stats(result, stats_file)}[/dim]"
            )

    _guard(action)


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
@app.command()
def verify(
    ctx: typer.Context,
    target: str = typer.Option(..., "--target", help="The anonymized database to check."),
    rules: Path = typer.Option("masker.yaml", "--rules", help="Path to the rules file."),
    source: str = typer.Option(..., "--source", help="The original database to compare against."),
    sample_size: int = typer.Option(
        500, "--sample-size", min=1, help="Distinct values checked per masked column."
    ),
    check_fk: bool = typer.Option(
        True, "--check-fk/--no-check-fk", help="Also check for orphaned foreign keys."
    ),
    tables: list[str] | None = typer.Option(None, "--tables", help="Only check these."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of tables."),
) -> None:
    """Sample-check that no original masked value survives in the target."""

    def action() -> None:
        key = _resolve_key(ctx, required=True)
        assert key is not None
        loaded = load_rules(rules)
        result = verify_target(
            source_url=source,
            target_url=target,
            rules=loaded,
            key=key,
            sample_size=sample_size,
            check_fk=check_fk,
            tables=list(tables) if tables else None,
        )
        if as_json:
            get_console().print_json(json.dumps(result.to_dict()))
        else:
            _print_verify(result)
        if not result.ok:
            raise typer.Exit(EXIT_FAILURE)

    _guard(action)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@app.command()
def report(
    input_file: Path = typer.Option(
        Path(DEFAULT_STATS_FILE), "--input", "-i", help="Run summary JSON from `masker run`."
    ),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown or json."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write to this file instead of stdout."
    ),
) -> None:
    """Render the summary of a previous run."""

    def action() -> None:
        stats = load_stats(input_file)
        rendered = write_report(stats, fmt=fmt, output=output)
        if output is not None and str(output) != "-":
            get_console().print(f"[ok]Wrote[/ok] {output}")
        elif fmt == "json":
            # JSON is for machines: Rich would hard-wrap it at the terminal
            # width and produce text that no longer parses.
            typer.echo(rendered)
        else:
            get_console().print(rendered, markup=False, highlight=False)

    _guard(action)


# --------------------------------------------------------------------------- #
# transformers
# --------------------------------------------------------------------------- #
@app.command()
def transformers() -> None:
    """List the built-in transformers and their params."""

    def action() -> None:
        listing = rich_table("Transformers", "Name", "What it does", "Params")
        for name, cls in REGISTRY.items():
            params = ", ".join(
                f"{field_name}={field.default!r}"
                for field_name, field in cls.params_model.model_fields.items()
            )
            listing.add_row(name, cls.summary, params or "-")
        get_console().print(listing)

    _guard(action)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _print_issues(issues: list[Issue]) -> None:
    console = get_console()
    if not issues:
        console.print("[ok]Rules look good: no problems found.[/ok]")
        return
    styles = {"error": "[err]error[/err]", "warning": "[warn]warning[/warn]", "info": "info"}
    listing = rich_table("Validation", "Level", "Where", "Problem")
    for issue in sorted(issues, key=lambda i: (i.severity != "error", i.where)):
        listing.add_row(styles[issue.severity], issue.where, issue.message)
    console.print(listing)
    for issue in issues:
        if issue.severity == "error" and issue.hint:
            console.print(f"  [dim]{issue.where}:[/dim] {issue.hint}")
    errors = sum(1 for issue in issues if issue.severity == "error")
    warnings = sum(1 for issue in issues if issue.severity == "warning")
    console.print(
        f"\n{errors} error(s), {warnings} warning(s), {len(issues) - errors - warnings} note(s)."
    )


def _print_scan(result: ScanResult) -> None:
    console = get_console()
    if result.findings:
        findings = rich_table(
            "Suspected PII", "Column", "Category", "Detected by", "Suggestion", "Has rule"
        )
        for finding in sorted(result.findings, key=lambda f: (f.table, f.column)):
            if finding.explicit:
                state = "[ok]keep (reviewed)[/ok]"
            elif not finding.unmasked:
                state = f"[ok]{finding.current_transformer}[/ok]"
            elif finding.confidence in ("high", "medium"):
                state = "[err]MISSING[/err]"
            else:
                state = "[warn]none[/warn]"
            findings.add_row(
                finding.label,
                finding.category,
                finding.detected_by,
                finding.transformer,
                state,
            )
        console.print(findings)
    else:
        console.print("[ok]No columns look like PII.[/ok]")

    if result.unruled:
        unruled = rich_table("No rule", "Table", "Column")
        for table_name, column in sorted(result.unruled):
            unruled.add_row(table_name, column)
        console.print(unruled)

    console.print(
        f"\nScanned {result.tables_scanned} table(s), {result.columns_scanned} column(s), "
        f"{result.rows_sampled} sample row(s)."
    )
    gate = result.unmasked_suspected_pii
    if gate:
        console.print(
            f"[err]{len(gate)}[/err] suspected PII column(s) are unmasked: "
            + ", ".join(finding.label for finding in gate)
        )
        console.print("[dim]Add a rule, or re-run with --strict to fail.[/dim]")
    else:
        console.print("[ok]Every suspected PII column has a rule.[/ok]")


def _print_dry_run(plan: DryRunPlan) -> None:
    console = get_console()
    console.print("[hl]Dry run[/hl] -- nothing will be written.\n")
    listing = rich_table("Plan", "Table", "Action", "Masked", "Copied verbatim", "Deferred FK")
    for item in plan.tables:
        listing.add_row(
            item.table,
            item.action,
            str(len(item.masked)),
            ", ".join(item.unmasked) or "-",
            "yes" if item.deferred_constraints else "no",
        )
    console.print(listing)

    if plan.samples:
        samples = rich_table(
            "Sample (originals partially hidden)", "Column", "Transformer", "Before", "After"
        )
        for sample in plan.samples:
            samples.add_row(
                f"{sample.table}.{sample.column}",
                sample.transformer,
                sample.before,
                sample.after,
            )
        console.print(samples)

    for warning in plan.warnings:
        console.print(f"[warn]warning:[/warn] {warning}")


def _print_run(result: RunResult) -> None:
    console = get_console()
    listing = rich_table("Run", "Table", "Action", "Rows", "Masked", "Seconds")
    for item in result.tables:
        listing.add_row(
            item.table,
            item.action,
            str(item.rows_written),
            str(len(item.masked)),
            f"{item.duration_s:.3f}",
        )
    console.print(listing)
    console.print(
        f"\n{result.rows_written} row(s) in {len(result.tables)} table(s) "
        f"in {result.duration_s:.2f}s."
    )
    for warning in result.warnings:
        console.print(f"[warn]warning:[/warn] {warning}")
    if result.unmasked_columns:
        console.print(
            f"[warn]{len(result.unmasked_columns)}[/warn] column(s) copied verbatim: "
            + ", ".join(result.unmasked_columns)
        )


def _print_verify(result: VerifyResult) -> None:
    console = get_console()
    if result.checks:
        listing = rich_table("Leak check", "Column", "Transformer", "Sampled", "Matches")
        for check in sorted(result.checks, key=lambda c: (c.table, c.column)):
            if check.severity == "error":
                rendered = f"[err]{check.leaked}[/err]"
            elif check.severity == "warn":
                rendered = f"[warn]{check.leaked} ({check.rate:.0%})[/warn]"
            else:
                rendered = "[ok]0[/ok]"
            listing.add_row(check.label, check.transformer, str(check.sampled), rendered)
        console.print(listing)
    else:
        console.print("[warn]No masked columns to check.[/warn]")

    for check in result.leaks:
        console.print(
            f"[err]leak:[/err] {check.label} -- {check.leaked} original value(s) still "
            f"present, e.g. {', '.join(check.examples)}"
        )
    for check in result.coincidences:
        console.print(
            f"[warn]note:[/warn] {check.label} -- {check.leaked} of {check.sampled} masked "
            "values coincide with another row's original. Expected for jitter/shift "
            "transformers; widen the range if that matters."
        )

    if result.unruled:
        unruled = rich_table("No rule", "Column", "Rows", "Looks like", "Verdict")
        for entry in sorted(result.unruled, key=lambda c: (c.table, c.column)):
            if entry.severity == "error":
                verdict = "[err]UNMASKED PII[/err]"
            elif entry.explicit:
                verdict = "[warn]keep (reviewed)[/warn]"
            else:
                verdict = "[warn]verbatim[/warn]"
            unruled.add_row(entry.label, str(entry.rows), entry.category or "-", verdict)
        console.print(unruled)
        for entry in result.unmasked_pii:
            console.print(
                f"[err]unmasked:[/err] {entry.label} has no rule and looks like "
                f"{entry.category}; {entry.rows} row(s) were copied verbatim."
            )

    if result.orphans:
        fks = rich_table("Foreign keys", "Relationship", "Orphans")
        for relationship in result.orphans:
            fks.add_row(
                relationship.label,
                f"[err]{relationship.orphans}[/err]" if relationship.orphans else "[ok]0[/ok]",
            )
        console.print(fks)

    if result.ok:
        console.print(f"\n[ok]No leaks found[/ok] across {len(result.checks)} masked column(s).")
    else:
        console.print(
            f"\n[err]{result.total_leaked}[/err] leaked value(s), "
            f"{len(result.unmasked_pii)} unmasked PII column(s), "
            f"{len(result.broken_fks)} broken foreign key(s)."
        )


class _RichProgress:
    """A :class:`~masker.engine.ProgressSink` backed by Rich."""

    def __init__(self) -> None:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.fields[table]}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=get_console(),
            transient=True,
        )
        self._task: Any = None
        self._progress.start()

    def table_started(self, name: str, total: int | None) -> None:
        if self._task is not None:
            self._progress.remove_task(self._task)
        self._task = self._progress.add_task("copy", total=total, table=name)

    def advance(self, rows: int) -> None:
        if self._task is not None:
            self._progress.advance(self._task, rows)

    def table_done(self, name: str, rows: int, seconds: float) -> None:
        if self._task is not None:
            self._progress.update(self._task, completed=rows, total=rows)

    def stop(self) -> None:
        self._progress.stop()


def main() -> None:
    """Entry point for the ``masker`` console script."""
    app()
