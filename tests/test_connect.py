"""Safety guards: same-database refusal, read-only sources, credential redaction."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from masker.connect import (
    SQLITE_MEMORY_IDENTITY,
    database_identity,
    is_same_database,
    make_engine,
    mask_value,
    redact_text,
    redact_url,
    require_different_databases,
    source_engine,
    target_engine,
    target_is_empty,
)
from masker.errors import SafetyError

PG = "postgresql+psycopg://user:s3cret@db.internal:5432/app"


# --------------------------------------------------------------------------- #
# Same-database detection
# --------------------------------------------------------------------------- #
def test_the_same_sqlite_file_is_the_same_database(source_db: Path) -> None:
    assert is_same_database(f"sqlite:///{source_db}", f"sqlite:///{source_db.resolve()}")


def test_a_different_sqlite_file_is_a_different_database(tmp_path: Path) -> None:
    assert not is_same_database(f"sqlite:///{tmp_path}/a.sqlite", f"sqlite:///{tmp_path}/b.sqlite")


def test_two_in_memory_databases_are_never_the_same() -> None:
    assert database_identity("sqlite://") == SQLITE_MEMORY_IDENTITY
    assert not is_same_database("sqlite://", "sqlite://")


def test_postgres_identity_ignores_credentials() -> None:
    assert database_identity(PG) == database_identity("postgresql://other:pw@DB.internal:5432/APP")


def test_postgres_identity_uses_the_default_port() -> None:
    assert database_identity("postgresql://u:p@host/app") == database_identity(
        "postgresql://u:p@host:5432/app"
    )


def test_mysql_identity_uses_the_default_port() -> None:
    assert database_identity("mysql+pymysql://u:p@host/app") == database_identity(
        "mysql+pymysql://u:p@host:3306/app"
    )


def test_require_different_databases_refuses_the_same_one(source_db: Path) -> None:
    url = f"sqlite:///{source_db}"
    with pytest.raises(SafetyError, match="same database"):
        require_different_databases(url, url)


def test_require_different_databases_allows_separate_files(tmp_path: Path) -> None:
    require_different_databases(f"sqlite:///{tmp_path}/a.sqlite", f"sqlite:///{tmp_path}/b.sqlite")


# --------------------------------------------------------------------------- #
# Read-only sources
# --------------------------------------------------------------------------- #
def test_sqlite_source_is_opened_read_only(source_url: str) -> None:
    with source_engine(source_url) as engine:
        assert "mode=ro" in str(engine.url)
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one() == 20
            with pytest.raises(OperationalError, match="readonly"):
                conn.execute(text("DELETE FROM users"))


def test_in_memory_sqlite_is_left_alone() -> None:
    with source_engine("sqlite://") as engine:
        assert "mode=ro" not in str(engine.url)


def test_postgres_read_only_sets_the_execution_option() -> None:
    from masker.connect import _read_only_kwargs

    assert _read_only_kwargs("postgresql", read_only=True)["execution_options"] == {
        "postgresql_readonly": True
    }


def test_mysql_read_only_uses_an_init_command() -> None:
    from masker.connect import MYSQL_READ_ONLY_COMMAND, _read_only_kwargs

    assert _read_only_kwargs("mysql", read_only=True)["connect_args"] == {
        "init_command": MYSQL_READ_ONLY_COMMAND
    }
    assert _read_only_kwargs("mariadb", read_only=True)["connect_args"] == {
        "init_command": MYSQL_READ_ONLY_COMMAND
    }


def test_read_only_kwargs_are_absent_when_not_asked_for() -> None:
    from masker.connect import _read_only_kwargs

    assert _read_only_kwargs("postgresql", read_only=False) == {
        "future": True,
        "hide_parameters": True,
    }
    assert "execution_options" not in _read_only_kwargs("mysql", read_only=False)
    # SQLite is handled by rewriting the URL, not by engine kwargs.
    assert _read_only_kwargs("sqlite", read_only=True) == {"future": True, "hide_parameters": True}


def test_target_engine_is_writable(tmp_path: Path) -> None:
    path = tmp_path / "writable.sqlite"
    with target_engine(f"sqlite:///{path}") as engine, engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (id INTEGER)"))
    assert path.exists()


def test_an_unusable_driver_url_is_reported() -> None:
    with pytest.raises(SafetyError, match="Could not create an engine"):
        make_engine("nosuchdb://user:pw@host/app")


# --------------------------------------------------------------------------- #
# Target emptiness
# --------------------------------------------------------------------------- #
def test_a_fresh_database_is_empty(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path}/fresh.sqlite")
    assert target_is_empty(engine)
    engine.dispose()


def test_a_database_with_a_table_is_not_empty(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path}/used.sqlite")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (id INTEGER)"))
    assert not target_is_empty(engine)
    engine.dispose()


def test_an_unreadable_target_is_reported(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path}/missing/dir.sqlite")
    with pytest.raises(SafetyError, match="Could not inspect"):
        target_is_empty(engine)
    engine.dispose()


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
def test_passwords_are_hidden_in_urls() -> None:
    rendered = redact_url(PG)
    assert "s3cret" not in rendered
    assert "***" in rendered


def test_sqlite_urls_are_rendered_readably(source_db: Path) -> None:
    rendered = redact_url(f"sqlite:///{source_db}?mode=ro&uri=true")
    assert "file%3A" not in rendered
    assert "mode=ro" in rendered


def test_an_unparsable_url_does_not_raise() -> None:
    assert redact_url("not a url at all :::") == "<unparsable-database-url>"


def test_password_pairs_are_scrubbed_from_messages() -> None:
    message = "connection failed: password=hunter2 host=db"
    assert redact_text(message) == "connection failed: password=**** host=db"


def test_url_userinfo_is_scrubbed_from_messages() -> None:
    scrubbed = redact_text(f"died connecting to {PG}")
    assert "s3cret" not in scrubbed
    assert "user" not in scrubbed.split("@")[0]


def test_known_secrets_are_scrubbed() -> None:
    assert redact_text("key was abcdef0123", secrets=["abcdef0123"]) == "key was ****"


def test_short_secrets_are_left_alone() -> None:
    assert redact_text("ab", secrets=["ab"]) == "ab"


def test_mask_value_hides_the_middle() -> None:
    assert mask_value("hello@example.com") == "h**************om"
    assert mask_value(None) == "NULL"
    assert mask_value("ab") == "***"
    assert mask_value(12345) == "1**45"


def test_driver_hints_point_at_the_extra() -> None:
    # The hint is only attached when the driver import fails, which depends on
    # which extras are installed, so assert the helper directly.
    from masker.connect import _driver_hint

    assert (
        _driver_hint("postgresql") == "Install the driver with: pip install 'masker-db[postgres]'"
    )
    assert _driver_hint("mysql") == "Install the driver with: pip install 'masker-db[mysql]'"
    assert _driver_hint("mariadb") == "Install the driver with: pip install 'masker-db[mysql]'"
    assert _driver_hint("sqlite") is None


def test_a_missing_driver_reports_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def deny_psycopg(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("psycopg"):
            raise ImportError("No module named 'psycopg'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", deny_psycopg)
    with pytest.raises(SafetyError, match=r"masker-db\[postgres\]"):
        make_engine(PG)


def test_identity_of_a_url_without_credentials(tmp_path: Path) -> None:
    assert database_identity(f"sqlite:///{tmp_path}/a.sqlite").startswith("sqlite://")
