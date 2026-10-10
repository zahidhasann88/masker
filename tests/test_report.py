"""Run summaries: persisting, loading and rendering reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from masker.engine import RunResult, TableResult
from masker.errors import MaskerError
from masker.report import DEFAULT_STATS_FILE, load_stats, render_markdown, save_stats, write_report


@pytest.fixture
def result() -> RunResult:
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    return RunResult(
        started_at=started,
        finished_at=started,
        duration_s=12.3456,
        source="postgresql://user:***@db/app",
        target="postgresql://user:***@db/app_masked",
        batch_size=5000,
        dry_run=False,
        tables=[
            TableResult(
                table="users",
                action="copy",
                rows_read=10_000,
                rows_written=10_000,
                duration_s=8.0,
                masked={"email": "email", "ssn": "hash(length=12)"},
                unmasked=["created_at"],
                unique_retries=3,
                deferred_constraints=False,
            ),
            TableResult(
                table="audit_log",
                action="skip",
                rows_read=0,
                rows_written=0,
                duration_s=0.0,
                masked={},
                unmasked=[],
                unique_retries=0,
                deferred_constraints=False,
            ),
        ],
        warnings=["orders has a self-referencing foreign key."],
        created_schema=True,
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def test_stats_round_trip(result: RunResult, tmp_path: Path) -> None:
    path = save_stats(result, tmp_path / "nested" / "last_run.json")
    assert path.is_file()
    loaded = load_stats(path)
    assert loaded["totals"]["rows_written"] == 10_000
    assert loaded["batch_size"] == 5000


def test_stats_are_sorted_json(result: RunResult, tmp_path: Path) -> None:
    path = save_stats(result, tmp_path / "run.json")
    text = path.read_text(encoding="utf-8")
    assert list(json.loads(text)) == sorted(json.loads(text))


def test_loading_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(MaskerError, match="No run summary"):
        load_stats(tmp_path / "absent.json")


def test_loading_broken_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(MaskerError, match="not valid JSON"):
        load_stats(path)


def test_loading_a_non_object(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(MaskerError, match="does not contain a run summary"):
        load_stats(path)


def test_default_stats_path_is_relative() -> None:
    assert DEFAULT_STATS_FILE == ".masker/last_run.json"


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def test_markdown_report_covers_the_run(result: RunResult) -> None:
    markdown = render_markdown(result.to_dict())
    assert "# Masker run summary" in markdown
    assert "10000" in markdown  # rows read/written
    assert "users" in markdown
    assert "audit_log" in markdown
    assert "email" in markdown
    assert "created_at" in markdown  # unmasked columns are listed
    assert "self-referencing" in markdown  # warnings carried through
    assert "12.35" in markdown  # duration
    assert "***" in markdown  # credentials stay redacted


def test_markdown_report_of_a_dry_run(result: RunResult) -> None:
    payload = result.to_dict()
    payload["dry_run"] = True
    assert "dry run" in render_markdown(payload).lower()


def test_markdown_report_with_no_tables() -> None:
    payload = {
        "started_at": "2026-01-02T03:04:05+00:00",
        "finished_at": "2026-01-02T03:04:05+00:00",
        "duration_s": 0.0,
        "source": "sqlite:///a.sqlite",
        "target": "sqlite:///b.sqlite",
        "batch_size": 5000,
        "dry_run": False,
        "created_schema": False,
        "totals": {
            "tables": 0,
            "rows_read": 0,
            "rows_written": 0,
            "masked_columns": 0,
            "unmasked_columns": 0,
        },
        "warnings": [],
        "tables": [],
    }
    assert "# Masker run summary" in render_markdown(payload)


def test_json_format_is_the_stats_themselves(result: RunResult) -> None:
    payload = result.to_dict()
    assert json.loads(write_report(payload, fmt="json")) == payload


def test_writing_to_a_file(tmp_path: Path, result: RunResult) -> None:
    out = tmp_path / "report" / "run.md"
    write_report(result.to_dict(), output=out)
    assert out.is_file()
    assert "# Masker run summary" in out.read_text(encoding="utf-8")


def test_writing_to_stdout_is_a_no_op(result: RunResult) -> None:
    # "-" means stdout; write_report must not create a file called "-"
    rendered = write_report(result.to_dict(), output="-")
    assert "# Masker run summary" in rendered
    assert not Path("-").exists()


def test_unknown_format(result: RunResult) -> None:
    with pytest.raises(MaskerError, match="Unknown report format"):
        write_report(result.to_dict(), fmt="yaml")


def test_durations_are_humanised() -> None:
    from masker.report import _seconds

    assert _seconds(0.4) == "400 ms"
    assert _seconds(12.3456) == "12.35 s"
    assert _seconds(75) == "1m 15.0s"
    assert _seconds("not-a-number") == "?"


def test_result_totals(result: RunResult) -> None:
    assert result.rows_read == 10_000
    assert result.rows_written == 10_000
    assert result.masked_column_count == 2
    assert result.unmasked_columns == ["users.created_at"]
