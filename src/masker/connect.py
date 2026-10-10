"""Database connections and the safety guards that wrap them.

Responsibilities:

* build engines with a **read-only** source connection wherever the backend
  supports it,
* decide whether two URLs point at the same database,
* scrub credentials out of every URL and message Masker prints.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import url2pathname

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.exc import SQLAlchemyError

from masker.errors import SafetyError

__all__ = [
    "DEFAULT_PORTS",
    "SQLITE_MEMORY_IDENTITY",
    "database_identity",
    "is_same_database",
    "make_engine",
    "mask_value",
    "redact_text",
    "redact_url",
    "require_different_databases",
    "source_engine",
    "target_engine",
    "target_is_empty",
]

#: Identity string for SQLite in-memory databases.
SQLITE_MEMORY_IDENTITY = "sqlite://:memory:"

#: Ports assumed when a URL omits one, used for identity comparison only.
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "mariadb": 3306, "mssql": 1433, "oracle": 1521}

_CREDENTIAL_PAIR = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&'\"]+)"
)
_USERINFO = re.compile(r"(://)([^/@\s]+)(@)")


# --------------------------------------------------------------------------- #
# URL handling
# --------------------------------------------------------------------------- #
def redact_url(url: str | URL) -> str:
    """Render a URL with the password hidden. Never raises."""
    try:
        parsed = make_url(url)
    except Exception:  # pragma: no cover - defensive, unreachable for valid URLs
        return "<unparsable-database-url>"
    parsed = parsed.set(
        query={
            key: "****" if re.search(r"(?i)(password|passwd|pwd|secret|token|key)", key) else value
            for key, value in parsed.query.items()
        }
    )
    if parsed.get_backend_name() == "sqlite":
        # SQLite URLs carry no credentials; render by hand so the ``file:``
        # prefix is not percent-encoded into something unreadable.
        query = "&".join(f"{key}={value}" for key, value in parsed.query.items())
        rendered = f"sqlite:///{parsed.database or ':memory:'}"
        return f"{rendered}?{query}" if query else rendered
    return parsed.render_as_string(hide_password=True)


def redact_text(message: str, secrets: Iterable[str] = ()) -> str:
    """Scrub credentials from an arbitrary message.

    Handles three shapes: ``password=...`` style pairs, ``user:pass@`` URL
    userinfo, and any literal secret the caller knows about (for example the
    masking key, so it can never leak into an error message).
    """
    scrubbed = _CREDENTIAL_PAIR.sub(r"\1\2****", message)
    scrubbed = _USERINFO.sub(r"\1***:***\3", scrubbed)
    for secret in secrets:
        if len(secret) >= 4:
            scrubbed = scrubbed.replace(secret, "****")
    return scrubbed


def database_identity(url: str | URL) -> str:
    """A canonical string identifying *which database* a URL points at.

    Credentials and driver flavours are ignored: two URLs that differ only in
    user, password or driver variant still identify the same database.
    """
    parsed = make_url(url)
    backend = parsed.get_backend_name()

    if backend == "sqlite":
        database = parsed.database or ""
        if database in ("", ":memory:"):
            return SQLITE_MEMORY_IDENTITY
        if database.startswith("file:"):
            if parsed.query.get("mode") == "memory":
                raise SafetyError("Named SQLite memory databases are not supported safely.")
            database = url2pathname(urlsplit(database).path)
        return f"sqlite://{os.path.normcase(os.path.realpath(database))}"

    host = (parsed.host or "localhost").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        host = "localhost"
    port = parsed.port or DEFAULT_PORTS.get(backend, 0)
    database = (parsed.database or "").lower()
    return f"{backend}://{host}:{port}/{database}"


def is_same_database(source_url: str | URL, target_url: str | URL) -> bool:
    """``True`` when both URLs address the same physical database.

    Two ``sqlite://`` (in-memory) URLs are *never* the same database: every
    engine owns its own private in-memory database, so Masker cannot write to
    the source through the target connection.
    """
    source = database_identity(source_url)
    if source == SQLITE_MEMORY_IDENTITY:
        return False
    target = database_identity(target_url)
    if source == target:
        return True
    if source.startswith("sqlite://") and target.startswith("sqlite://"):
        try:
            return os.path.samefile(source[len("sqlite://") :], target[len("sqlite://") :])
        except OSError:
            return False
    return False


def require_different_databases(source_url: str | URL, target_url: str | URL) -> None:
    """Refuse to run when source and target are the same database."""
    if is_same_database(source_url, target_url):
        raise SafetyError(
            f"Source and target resolve to the same database: {database_identity(source_url)}",
            hint=(
                "Masker never writes to the database it reads from. Point --target at a "
                "separate database (a different file, database or server)."
            ),
        )


# --------------------------------------------------------------------------- #
# Engine construction
# --------------------------------------------------------------------------- #
def make_engine(url: str | URL, *, read_only: bool = False) -> Engine:
    """Create an engine, opening it read-only when asked and supported.

    * **PostgreSQL** -- ``postgresql_readonly`` execution option plus
      ``SET default_transaction_read_only = on`` on connect.
    * **MySQL/MariaDB** -- ``SET SESSION TRANSACTION READ ONLY`` via the
      driver's ``init_command``.
    * **SQLite** -- URI mode with ``mode=ro``.
    """
    parsed = make_url(url)
    backend = parsed.get_backend_name()
    kwargs = _read_only_kwargs(backend, read_only=read_only)
    if read_only and backend == "sqlite":
        parsed = _sqlite_readonly_url(parsed)

    try:
        if parsed.drivername == "postgresql":
            parsed = parsed.set(drivername="postgresql+psycopg")
        elif parsed.drivername in ("mysql", "mariadb"):
            parsed = parsed.set(drivername=f"{backend}+pymysql")
        engine = create_engine(parsed, **kwargs)
    except Exception as exc:  # driver import errors are user facing
        raise SafetyError(
            f"Could not create an engine for {redact_url(parsed)}: {redact_text(str(exc))}",
            hint=_driver_hint(backend),
        ) from exc

    if read_only and backend == "postgresql":
        _install_postgres_readonly(engine)

    return engine


@contextmanager
def source_engine(url: str | URL) -> Iterator[Engine]:
    """A read-only engine for the source database."""
    engine = make_engine(url, read_only=True)
    try:
        yield engine
    finally:
        engine.dispose()


@contextmanager
def target_engine(url: str | URL) -> Iterator[Engine]:
    """A read/write engine for the target database."""
    engine = make_engine(url, read_only=False)
    try:
        yield engine
    finally:
        engine.dispose()


def target_is_empty(engine: Engine) -> bool:
    """``True`` when the target has no tables at all."""
    try:
        inspector = inspect(engine)
        tables = list(inspector.get_table_names())
        for schema in inspector.get_schema_names() if engine.dialect.name == "postgresql" else []:
            if schema in (
                "information_schema",
                "pg_catalog",
                "sys",
                "mysql",
                "performance_schema",
            ):
                continue
            tables.extend(inspector.get_table_names(schema=schema))
        return not tables
    except SQLAlchemyError as exc:
        raise SafetyError(
            f"Could not inspect the target database: {redact_text(str(exc))}"
        ) from exc


def mask_value(value: Any, *, keep_first: int = 1, keep_last: int = 2) -> str:
    """Partially hide a value so it can be shown in dry-runs and reports."""
    if value is None:
        return "NULL"
    text_value = str(value)
    if len(text_value) <= keep_first + keep_last:
        return "*" * max(len(text_value), 3)
    hidden = len(text_value) - keep_first - keep_last
    return f"{text_value[:keep_first]}{'*' * hidden}{text_value[-keep_last:]}"


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #
#: Sent to MySQL/MariaDB on connect so every transaction is read-only.
MYSQL_READ_ONLY_COMMAND = "SET SESSION TRANSACTION READ ONLY"


def _read_only_kwargs(backend: str, *, read_only: bool) -> dict[str, Any]:
    """Engine keyword arguments that make a connection read-only, per backend.

    Kept separate from engine construction so the behaviour is testable
    without the server-side drivers installed.
    """
    kwargs: dict[str, Any] = {"future": True, "hide_parameters": True}
    if not read_only:
        return kwargs
    if backend == "postgresql":
        kwargs["execution_options"] = {"postgresql_readonly": True}
    elif backend in ("mysql", "mariadb"):
        kwargs["connect_args"] = {"init_command": MYSQL_READ_ONLY_COMMAND}
    return kwargs


def _sqlite_readonly_url(url: URL) -> URL:
    """Rewrite a file-based SQLite URL into read-only URI mode.

    ``sqlite3`` only honours ``mode=ro`` when opened with ``uri=True``, and the
    URI form is what ``Path.as_uri()`` produces (which is also the form SQLite
    expects on Windows).
    """
    database = url.database or ""
    if database in ("", ":memory:"):
        return url
    query = dict(url.query)
    query["mode"] = "ro"
    query["uri"] = "true"
    if database.startswith("file:"):
        readonly_database = database
    else:
        readonly_database = Path(database).resolve().as_uri()
    return url.set(database=readonly_database, query=query)


def _install_postgres_readonly(engine: Engine) -> None:  # pragma: no cover - needs Postgres
    @event.listens_for(engine, "connect")
    def _set_read_only(dbapi_connection: Any, _record: Any) -> None:
        old_autocommit = dbapi_connection.autocommit
        dbapi_connection.autocommit = True
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SET default_transaction_read_only = on")
        finally:
            cursor.close()
            dbapi_connection.autocommit = old_autocommit


def _supports_schemas(engine: Engine) -> bool:
    return engine.dialect.name in ("postgresql", "mysql", "mariadb", "mssql", "oracle")


def _driver_hint(backend: str) -> str | None:
    hints = {
        "postgresql": "Install the driver with: pip install 'masker-db[postgres]'",
        "mysql": "Install the driver with: pip install 'masker-db[mysql]'",
        "mariadb": "Install the driver with: pip install 'masker-db[mysql]'",
    }
    return hints.get(backend)


def quote_identifier(name: str) -> str:  # pragma: no cover - used by diagnostics only
    """Quote an identifier for use in hand-written SQL (FK checks)."""
    return '"' + name.replace('"', '""') + '"'


def sanity_select_one(engine: Engine) -> int:  # pragma: no cover - smoke helper
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT 1")).scalar_one())
