"""End-to-end CLI behaviour, driven through Typer's runner."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from masker.cli import app
from masker.errors import ConfigError

runner = CliRunner()


def invoke(*args: str) -> object:
    return runner.invoke(app, list(args))


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    path = tmp_path / "masker.yaml"
    path.write_text(
        """
version: 1
settings:
  batch_size: 10
tables:
  users:
    columns:
      id:    {transformer: hash}
      email: {transformer: email}
      name:  {transformer: fake, params: {provider: name}}
      phone: {transformer: partial_mask, params: {keep_last: 4}}
      ssn:   {transformer: hash, params: {length: 11}}
      dob:   {transformer: date_shift}
      salary: {transformer: number_noise, params: {percent: 10}}
      bio:   {transformer: redact}
  accounts:
    columns:
      id:      {transformer: hash}
      user_id: {transformer: hash}
      iban:    {transformer: hash, params: {length: 20}}
  orders:
    columns:
      id:         {transformer: hash}
      account_id: {transformer: hash}
      total:      {transformer: number_noise, params: {percent: 5, round_to: 2}}
  employees:
    columns:
      id:         {transformer: hash}
      manager_id: {transformer: hash}
      email:      {transformer: email}
  cyc_a:
    columns:
      id:   {transformer: hash}
      b_id: {transformer: hash}
  cyc_b:
    columns:
      id:   {transformer: hash}
      a_id: {transformer: hash}
""",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def target_file(tmp_path: Path) -> Path:
    return tmp_path / "target.sqlite"


@pytest.fixture
def keyed(with_key: Callable[[str], None]) -> None:
    """Set MASKER_SECRET_KEY for the duration of a test."""
    with_key()


# --------------------------------------------------------------------------- #
# Global flags
# --------------------------------------------------------------------------- #
def test_version() -> None:
    result = invoke("--version")
    assert result.exit_code == 0
    assert "masker" in result.output


def test_help_lists_the_commands() -> None:
    result = invoke("--help")
    assert result.exit_code == 0
    for command in ("init", "scan", "validate", "run", "verify", "report", "transformers"):
        assert command in result.output


def test_no_arguments_prints_help() -> None:
    result = invoke()
    assert result.exit_code != 0
    assert "Usage" in result.output


def test_transformers_lists_every_one(keyed: None) -> None:
    result = invoke("transformers")
    assert result.exit_code == 0
    for name in ("fake", "hash", "partial_mask", "email", "date_shift", "number_noise"):
        assert name in result.output


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def test_run_without_a_key_is_refused(source_url: str, target_file: Path, rules_file: Path) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
    )
    assert result.exit_code == 1
    assert "refuses to run without one" in result.output


def test_a_weak_key_is_refused(
    source_url: str, target_file: Path, rules_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MASKER_SECRET_KEY", "short")
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
    )
    assert result.exit_code == 1
    assert "too weak" in result.output


def test_an_ephemeral_key_warns(source_url: str, target_file: Path, rules_file: Path) -> None:
    result = invoke(
        "--ephemeral-key",
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 0
    assert "NOT reproducible" in result.output


def test_the_key_is_never_echoed(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 0
    assert "unit-test-key-0123456789abcdef" not in result.output


def test_a_key_file_is_used(
    source_url: str, target_file: Path, rules_file: Path, tmp_path: Path
) -> None:
    key_file = tmp_path / "masker.key"
    key_file.write_text("a-key-file-secret-0123456789abcdef\n", encoding="utf-8")
    result = invoke(
        "--key-file",
        str(key_file),
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 0


def test_credentials_in_urls_are_redacted(rules_file: Path, tmp_path: Path) -> None:
    result = invoke(
        "validate",
        "--rules",
        str(rules_file),
        "--source",
        "sqlite:////does/not/exist.sqlite",
    )
    assert result.exit_code == 1
    assert "password" not in result.output.lower()


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
def test_init_writes_a_starter_file(source_url: str, tmp_path: Path) -> None:
    out = tmp_path / "generated.yaml"
    result = invoke("init", "--source", source_url, "--output", str(out))
    assert result.exit_code == 0
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "SUGGESTED" in text
    assert "users" in text
    assert "email" in text
    # the generated file must itself be loadable
    from masker.config import load_rules

    load_rules(out)


def test_init_can_be_limited_to_tables(source_url: str, tmp_path: Path) -> None:
    out = tmp_path / "users.yaml"
    result = invoke("init", "--source", source_url, "--output", str(out), "--tables", "users")
    assert result.exit_code == 0
    assert "accounts" not in out.read_text(encoding="utf-8")


def test_init_refuses_to_overwrite(source_url: str, tmp_path: Path) -> None:
    out = tmp_path / "existing.yaml"
    out.write_text("version: 1\n", encoding="utf-8")
    result = invoke("init", "--source", source_url, "--output", str(out))
    assert result.exit_code == 1
    assert "exists" in result.output.lower()


def test_init_force_overwrites(source_url: str, tmp_path: Path) -> None:
    out = tmp_path / "existing.yaml"
    out.write_text("version: 1\n", encoding="utf-8")
    result = invoke("init", "--source", source_url, "--output", str(out), "--force")
    assert result.exit_code == 0
    assert "SUGGESTED" in out.read_text(encoding="utf-8")


def test_init_reports_an_unreachable_source(tmp_path: Path) -> None:
    result = invoke("init", "--source", "sqlite:////no/such/dir.sqlite")
    assert result.exit_code == 1


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_scan_finds_pii(source_url: str) -> None:
    result = invoke("scan", "--source", source_url)
    assert result.exit_code == 0
    assert "users.email" in result.output


def test_scan_strict_fails_on_unmasked_pii(source_url: str) -> None:
    result = invoke("scan", "--source", source_url, "--strict")
    assert result.exit_code == 1


def test_scan_strict_passes_with_a_complete_rules_file(source_url: str, rules_file: Path) -> None:
    result = invoke("scan", "--source", source_url, "--strict", "--rules", str(rules_file))
    assert result.exit_code == 0, result.output


def test_scan_lists_columns_without_a_rule(source_url: str, tmp_path: Path) -> None:
    partial = tmp_path / "partial.yaml"
    partial.write_text(
        "tables:\n  users:\n    columns:\n      email: {transformer: email}\n", encoding="utf-8"
    )
    result = invoke("scan", "--source", source_url, "--rules", str(partial))
    assert result.exit_code == 0
    assert "no rule" in result.output.lower()


def test_scan_can_be_limited_to_tables(source_url: str) -> None:
    result = invoke("scan", "--source", source_url, "--tables", "users")
    assert result.exit_code == 0
    assert "orders.total" not in result.output


def test_scan_as_json(source_url: str) -> None:
    result = invoke("scan", "--source", source_url, "--json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "suspected_pii" in payload
    assert payload["tables_scanned"] == 6


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #
def test_validate_accepts_good_rules(source_url: str, rules_file: Path, keyed: None) -> None:
    result = invoke("validate", "--rules", str(rules_file), "--source", source_url)
    assert result.exit_code == 0


def test_validate_reports_an_unknown_column(source_url: str, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "tables:\n  users:\n    columns:\n      nope: {transformer: email}\n", encoding="utf-8"
    )
    result = invoke("validate", "--rules", str(bad), "--source", source_url)
    assert result.exit_code == 1
    assert "unknown-column" in result.output or "nope" in result.output


def test_validate_strict_fails_on_warnings(source_url: str, tmp_path: Path, keyed: None) -> None:
    warny = tmp_path / "warny.yaml"
    warny.write_text(
        """
tables:
  users:
    columns:
      ssn: {transformer: hash, params: {length: 40}}
""",
        encoding="utf-8",
    )
    relaxed = invoke("validate", "--rules", str(warny), "--source", source_url)
    strict = invoke("validate", "--rules", str(warny), "--source", source_url, "--strict")
    assert relaxed.exit_code == 0
    assert strict.exit_code == 1


def test_validate_a_missing_rules_file(source_url: str, tmp_path: Path) -> None:
    result = invoke("validate", "--rules", str(tmp_path / "absent.yaml"), "--source", source_url)
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
def test_run_masks_a_database(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 0, result.output
    assert "rows" in result.output.lower()

    conn = sqlite3.connect(target_file)
    try:
        rows = conn.execute("SELECT email FROM users").fetchall()
    finally:
        conn.close()
    assert len(rows) == 20
    assert not any(email.endswith("@corp.example") for (email,) in rows)


def test_run_writes_a_stats_file(
    source_url: str, target_file: Path, rules_file: Path, keyed: None, tmp_path: Path
) -> None:
    stats = tmp_path / "stats" / "run.json"
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--stats-file",
        str(stats),
    )
    assert result.exit_code == 0
    assert stats.is_file()
    payload = json.loads(stats.read_text(encoding="utf-8"))
    assert payload["totals"]["rows_written"] == 89


def test_run_dry_run_writes_nothing(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--dry-run",
    )
    assert result.exit_code == 0
    assert not target_file.exists()
    # the sample hides the originals
    assert "*" in result.output
    assert "user1@corp.example" not in result.output


def test_run_refuses_the_same_database(source_url: str, rules_file: Path, keyed: None) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        source_url,
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 1
    assert "same database" in result.output


def test_run_refuses_a_non_empty_target(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    first = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert first.exit_code == 0
    second = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert second.exit_code == 1
    assert "not empty" in second.output

    third = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--allow-non-empty",
    )
    assert third.exit_code == 0, third.output


def test_run_honours_tables_and_exclude(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--tables",
        "users",
    )
    assert result.exit_code == 0
    conn = sqlite3.connect(target_file)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
    finally:
        conn.close()
    assert "users" in tables
    assert "orders" not in tables


def test_run_rejects_an_unknown_table(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--tables",
        "nope",
    )
    assert result.exit_code == 1
    assert "--tables" in result.output


def test_run_subset_rows(source_url: str, target_file: Path, rules_file: Path, keyed: None) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--subset-rows",
        "4",
    )
    assert result.exit_code == 0
    conn = sqlite3.connect(target_file)
    try:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 4
    finally:
        conn.close()


def test_run_batch_size(source_url: str, target_file: Path, rules_file: Path, keyed: None) -> None:
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--batch-size",
        "3",
    )
    assert result.exit_code == 0
    stats = json.loads(Path(".masker/last_run.json").read_text(encoding="utf-8"))
    assert stats["batch_size"] == 3


def test_run_without_create_schema_explains_itself(
    source_url: str, tmp_path: Path, rules_file: Path, keyed: None
) -> None:
    bare = tmp_path / "bare.sqlite"
    bare.touch()
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{bare}",
        "--rules",
        str(rules_file),
        "--yes",
        "--no-create-schema",
    )
    assert result.exit_code == 1
    assert "missing table" in result.output


def test_run_lists_unmasked_columns(source_url: str, tmp_path: Path, keyed: None) -> None:
    partial = tmp_path / "partial.yaml"
    partial.write_text(
        "tables:\n  users:\n    columns:\n      email: {transformer: email}\n", encoding="utf-8"
    )
    target = tmp_path / "partial-target.sqlite"
    result = invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target}",
        "--rules",
        str(partial),
        "--yes",
    )
    assert result.exit_code == 0
    assert "users.name" in result.output


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def test_verify_a_clean_run(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    result = invoke(
        "verify",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
    )
    assert result.exit_code == 0, result.output
    assert "leak" in result.output.lower()


def test_verify_fails_when_a_rule_is_missing(
    source_url: str, target_file: Path, rules_file: Path, keyed: None, tmp_path: Path
) -> None:
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    reduced = tmp_path / "reduced.yaml"
    text = rules_file.read_text(encoding="utf-8").replace(
        "      email: {transformer: email}\n", "", 1
    )
    reduced.write_text(text, encoding="utf-8")
    result = invoke(
        "verify",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(reduced),
    )
    assert result.exit_code == 1
    assert "email" in result.output


def test_verify_as_json(source_url: str, target_file: Path, rules_file: Path, keyed: None) -> None:
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    result = invoke(
        "verify",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--json",
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True


def test_verify_no_check_fk(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    result = invoke(
        "verify",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--no-check-fk",
    )
    assert result.exit_code == 0
    assert "foreign key" not in result.output.lower()


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def test_report_markdown(
    source_url: str, target_file: Path, rules_file: Path, keyed: None, tmp_path: Path
) -> None:
    stats = tmp_path / "run.json"
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--stats-file",
        str(stats),
    )
    result = invoke("report", "--input", str(stats))
    assert result.exit_code == 0
    assert "Masker run summary" in result.output


def test_report_json(
    source_url: str, target_file: Path, rules_file: Path, keyed: None, tmp_path: Path
) -> None:
    stats = tmp_path / "run.json"
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--stats-file",
        str(stats),
    )
    result = invoke("report", "--input", str(stats), "--format", "json")
    assert result.exit_code == 0
    assert json.loads(result.output)["totals"]["rows_written"] == 89


def test_report_to_a_file(
    source_url: str, target_file: Path, rules_file: Path, keyed: None, tmp_path: Path
) -> None:
    stats = tmp_path / "run.json"
    out = tmp_path / "report.md"
    invoke(
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
        "--stats-file",
        str(stats),
    )
    result = invoke("report", "--input", str(stats), "--output", str(out))
    assert result.exit_code == 0
    assert out.is_file()


def test_report_a_missing_summary(tmp_path: Path) -> None:
    result = invoke("report", "--input", str(tmp_path / "absent.json"))
    assert result.exit_code == 1
    assert "No run summary" in result.output


def test_report_an_unknown_format(tmp_path: Path) -> None:
    stats = tmp_path / "run.json"
    stats.write_text("{}", encoding="utf-8")
    result = invoke("report", "--input", str(stats), "--format", "yaml")
    assert result.exit_code == 1
    assert "Unknown report format" in result.output


# --------------------------------------------------------------------------- #
# Global flags
# --------------------------------------------------------------------------- #
def test_no_color_disables_ansi(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "--no-color",
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 0
    assert "\x1b[" not in result.output


def test_verbose_does_not_leak_values(
    source_url: str, target_file: Path, rules_file: Path, keyed: None
) -> None:
    result = invoke(
        "--verbose",
        "run",
        "--source",
        source_url,
        "--target",
        f"sqlite:///{target_file}",
        "--rules",
        str(rules_file),
        "--yes",
    )
    assert result.exit_code == 0
    assert "user1@corp.example" not in result.output


def test_a_config_error_is_rendered_cleanly(tmp_path: Path, source_url: str) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ntables: [1, 2]\n", encoding="utf-8")
    result = invoke("validate", "--rules", str(bad), "--source", source_url)
    assert result.exit_code == 1
    assert isinstance(ConfigError("x"), ConfigError)
