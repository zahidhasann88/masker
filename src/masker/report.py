"""Run summaries as Markdown or JSON.

``masker run`` writes a machine-readable artifact (``.masker/last_run.json`` by
default) and ``masker report`` renders it. Keeping the two separate means a
long masking job can be summarised later, and the JSON can go straight into CI
output or a ticket.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from masker.engine import RunResult
from masker.errors import MaskerError

__all__ = [
    "DEFAULT_STATS_FILE",
    "load_stats",
    "render_markdown",
    "save_stats",
    "write_report",
]

DEFAULT_STATS_FILE = ".masker/last_run.json"


def save_stats(result: RunResult, path: str | Path = DEFAULT_STATS_FILE) -> Path:
    """Persist a run summary for ``masker report``."""
    stats_path = Path(path)
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return stats_path


def load_stats(path: str | Path = DEFAULT_STATS_FILE) -> dict[str, Any]:
    stats_path = Path(path)
    if not stats_path.is_file():
        raise MaskerError(
            f"No run summary at {stats_path}.",
            hint=(
                "Run 'masker run ...' first, or point --input at the JSON file "
                "written by a previous run."
            ),
        )
    try:
        loaded = json.loads(stats_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MaskerError(f"{stats_path} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise MaskerError(f"{stats_path} does not contain a run summary object.")
    return loaded


def write_report(
    stats: dict[str, Any],
    *,
    fmt: str = "markdown",
    output: str | Path | None = None,
) -> str:
    """Render a run summary; write it to ``output`` when given."""
    if fmt == "json":
        rendered = json.dumps(stats, indent=2, sort_keys=True)
    elif fmt == "markdown":
        rendered = render_markdown(stats)
    else:
        raise MaskerError(f"Unknown report format {fmt!r}.", hint="Use 'markdown' or 'json'.")

    if output is not None:
        output_path = Path(output)
        if str(output_path) != "-":
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered + "\n", encoding="utf-8")
    return rendered


def render_markdown(stats: dict[str, Any]) -> str:
    """Render a run summary as a Markdown document."""
    totals = stats.get("totals", {})
    tables = stats.get("tables", [])
    lines = [
        "# Masker run summary",
        "",
        f"- **Started:** {stats.get('started_at', '?')}",
        f"- **Duration:** {_seconds(stats.get('duration_s'))}",
        f"- **Source:** `{stats.get('source', '?')}`",
        f"- **Target:** `{stats.get('target', '?')}`",
        f"- **Batch size:** {stats.get('batch_size', '?')}",
        f"- **Schema created:** {'yes' if stats.get('created_schema') else 'no'}",
        f"- **Dry run:** {'yes' if stats.get('dry_run') else 'no'}",
        "",
        "## Totals",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Tables | {totals.get('tables', 0)} |",
        f"| Rows read | {totals.get('rows_read', 0)} |",
        f"| Rows written | {totals.get('rows_written', 0)} |",
        f"| Masked columns | {totals.get('masked_columns', 0)} |",
        f"| Unmasked columns | {totals.get('unmasked_columns', 0)} |",
        "",
        "## Tables",
        "",
        "| Table | Action | Rows in | Rows out | Masked | Unmasked | Seconds |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for table in tables:
        lines.append(
            "| {table} | {action} | {read} | {written} | "
            "{masked} | {unmasked} | {seconds} |".format(
                table=table.get("table", "?"),
                action=table.get("action", "?"),
                read=table.get("rows_read", 0),
                written=table.get("rows_written", 0),
                masked=len(table.get("masked", {})),
                unmasked=len(table.get("unmasked", [])),
                seconds=_seconds(table.get("duration_s")),
            )
        )

    masked = [
        (table.get("table"), column, spec)
        for table in tables
        for column, spec in table.get("masked", {}).items()
    ]
    if masked:
        lines += ["", "## Transformers applied", "", "| Column | Transformer |", "| --- | --- |"]
        for table_name, column, spec in sorted(masked):
            lines.append(f"| {table_name}.{column} | `{spec}` |")

    unmasked = [
        (table.get("table"), column) for table in tables for column in table.get("unmasked", [])
    ]
    lines += ["", "## Unmasked columns", ""]
    if unmasked:
        lines.append("These columns were copied verbatim. Confirm that is intentional:")
        lines += ["", "| Column |", "| --- |"]
        lines += [f"| {table_name}.{column} |" for table_name, column in sorted(unmasked)]
    else:
        lines.append("Every column in every copied table has a rule.")

    warnings = stats.get("warnings", [])
    lines += ["", "## Warnings", ""]
    if warnings:
        lines += [f"- {warning}" for warning in warnings]
    else:
        lines.append("None.")

    lines += [
        "",
        "---",
        "",
        "_Generated by [Masker](https://github.com/zahidhasann88/masker). Masking reduces "
        "disclosure risk; it is not a legal guarantee of anonymity._",
        "",
    ]
    return "\n".join(lines)


def _seconds(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "?"
    if value < 1:
        return f"{value * 1000:.0f} ms"
    if value < 60:
        return f"{value:.2f} s"
    minutes, seconds = divmod(value, 60)
    return f"{int(minutes)}m {seconds:.1f}s"
