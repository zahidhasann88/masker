"""PII heuristics for ``masker scan`` and ``masker init``.

Two independent signals, combined:

1. **column names** -- ``email``, ``ssn``, ``phone``, ``date_of_birth``, ...
   matched against a curated list of patterns, each carrying a suggested
   transformer;
2. **values** -- a small sample of each column is tested against shape
   detectors (email addresses, card numbers, IPv4, UUIDs, long free text).

Neither is a proof. A column can hold personal data with an innocuous name,
and a value can look like a card number without being one. Findings are
therefore always reported as suggestions, and free-text columns are called out
separately because masking them column-wise does not remove the names inside
them.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Table, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from masker.config import PASSTHROUGH_TRANSFORMERS, RulesFile
from masker.errors import SchemaError
from masker.schema import ColumnInfo, ReflectedSchema

__all__ = [
    "NON_GATING_CATEGORIES",
    "ColumnFinding",
    "NamePattern",
    "ScanResult",
    "ValuePattern",
    "match_name",
    "name_patterns",
    "scan_schema",
]


#: Reported, but not enough on their own to fail ``masker scan --strict``.
NON_GATING_CATEGORIES = frozenset({"free-text", "reference"})


# --------------------------------------------------------------------------- #
# Name patterns
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class NamePattern:
    """A column-name pattern and the rule Masker suggests for it."""

    pattern: str
    category: str
    transformer: str
    params: dict[str, Any] = field(default_factory=dict)
    #: ``high`` patterns are the ones ``--strict`` fails on.
    confidence: str = "high"

    def matches(self, column_name: str) -> bool:
        return re.search(self.pattern, column_name.lower()) is not None


_NAME_PATTERNS: tuple[NamePattern, ...] = (
    # Credentials first: these must never survive into a test database.
    NamePattern(r"(pass(word|wd)|pwd|secret|credential|private_key)", "credential", "redact"),
    NamePattern(r"(api[_-]?key|access[_-]?key|auth[_-]?token|token)", "credential", "redact"),
    NamePattern(r"(session|refresh)[_-]?token", "credential", "redact"),
    # Identifiers.
    NamePattern(
        r"(ssn|social[_-]?security|national[_-]?id|\bnid\b|passport|tax[_-]?id|\btin\b)",
        "government-id",
        "hash",
        {"length": 12},
    ),
    NamePattern(r"(driver|drivers)[_-]?(licen[cs]e|lic)", "government-id", "hash", {"length": 12}),
    NamePattern(
        r"(credit[_-]?card|card[_-]?number|\bcard\b|\bpan\b|\bcvv\b|\bcvc\b)",
        "card",
        "partial_mask",
        {"keep_last": 4},
    ),
    NamePattern(
        r"(iban|bank[_-]?account|account[_-]?number|routing[_-]?number)",
        "financial",
        "hash",
        {"length": 12},
    ),
    NamePattern(
        r"(salary|income|wage|compensation|payroll|balance)",
        "financial",
        "number_noise",
        {"percent": 10},
    ),
    # Contact details.
    NamePattern(r"(e[_-]?mail|mail[_-]?addr)", "email", "email", {"domain": "example.test"}),
    NamePattern(
        r"(phone|mobile|cell|fax|msisdn|telephone)", "phone", "partial_mask", {"keep_last": 4}
    ),
    # Network identifiers come before the generic ``address`` pattern:
    # "ip_address" is not a street address, and the specific rule must win.
    NamePattern(r"(ip[_-]?addr|ipv4|ipv6)", "network", "preserve_format", {}),
    NamePattern(r"(mac[_-]?addr)", "network", "preserve_format", {}),
    NamePattern(
        r"(user[_-]?agent|device[_-]?(id|name|token)|\bimei\b|\bidfa\b|advertising[_-]?id)",
        "device",
        "hash",
        {"length": 12},
        confidence="medium",
    ),
    NamePattern(
        r"(address|street|addr_line|line1|line2|(ship|billing|delivery)[_-]?(to|addr))",
        "address",
        "fake",
        {"provider": "street_address"},
    ),
    NamePattern(r"(city|town)", "address", "fake", {"provider": "city"}),
    NamePattern(r"(zip|postal|postcode)", "address", "preserve_format", {}),
    NamePattern(
        r"(country|region|state|province)",
        "address",
        "fake",
        {"provider": "country"},
        confidence="low",
    ),
    NamePattern(
        r"(latitude|longitude|\blat\b|\blng\b|\blon\b|geo)",
        "location",
        "number_noise",
        {"percent": 1},
    ),
    # Names of people and organisations.
    NamePattern(
        r"(user[_-]?name|login|handle|nickname|screen[_-]?name)",
        "username",
        "fake",
        {"provider": "user_name"},
    ),
    NamePattern(r"(first|given|fore)[_-]?name", "person", "fake", {"provider": "first_name"}),
    NamePattern(r"(last|family|sur)[_-]?name", "person", "fake", {"provider": "last_name"}),
    NamePattern(r"(middle|second)[_-]?name", "person", "fake", {"provider": "first_name"}),
    NamePattern(
        r"(full|display|real|contact|customer|patient|client|employee|user)[_-]?name",
        "person",
        "fake",
        {"provider": "name"},
    ),
    NamePattern(r"(^|_)name(_|$)", "person", "fake", {"provider": "name"}, confidence="medium"),
    NamePattern(
        r"(company|employer|organisation|organization|vendor)",
        "organisation",
        "fake",
        {"provider": "company"},
        confidence="medium",
    ),
    # Dates that identify people.
    NamePattern(
        r"(date[_-]?of[_-]?birth|\bdob\b|birth[_-]?date|born)",
        "birthdate",
        "date_shift",
        {"min_days": -30, "max_days": 30},
    ),
    # URLs and free text are reported, but never gate ``scan --strict``.
    NamePattern(
        r"(\burl\b|website|web[_-]?site|homepage)", "reference", "keep", {}, confidence="low"
    ),
    NamePattern(
        r"(notes?|comments?|remarks?|bio|description|summary|message|body|feedback|review)",
        "free-text",
        "keep",
        {},
        confidence="low",
    ),
)


def name_patterns() -> tuple[NamePattern, ...]:
    """The curated name patterns, in match order."""
    return _NAME_PATTERNS


def match_name(column_name: str) -> NamePattern | None:
    """The first name pattern matching ``column_name``, or ``None``."""
    return next((p for p in _NAME_PATTERNS if p.matches(column_name)), None)


# --------------------------------------------------------------------------- #
# Value patterns
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ValuePattern:
    """A shape detector applied to a sample of a column's values."""

    name: str
    category: str
    transformer: str
    check: Callable[[Any], bool]
    params: dict[str, Any] = field(default_factory=dict)
    #: ``high``/``medium`` findings count as suspected PII; ``low`` does not.
    confidence: str = "medium"


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")
_URL = re.compile(r"^https?://")
_DIGITS = re.compile(r"\d")


def _digits_only(value: Any) -> str:
    return re.sub(r"[^0-9]", "", str(value))


def _looks_like_email(value: Any) -> bool:
    return isinstance(value, str) and bool(_EMAIL.match(value.strip()))


def _looks_like_ipv4(value: Any) -> bool:
    if not isinstance(value, str) or not _IPV4.match(value.strip()):
        return False
    return all(0 <= int(part) <= 255 for part in value.strip().split("."))


def _looks_like_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.match(value.strip()))


def _looks_like_ssn(value: Any) -> bool:
    return isinstance(value, str) and bool(_SSN.match(value.strip()))


def _looks_like_iban(value: Any) -> bool:
    return isinstance(value, str) and bool(_IBAN.match(value.strip().upper().replace(" ", "")))


def _looks_like_url(value: Any) -> bool:
    return isinstance(value, str) and bool(_URL.match(value.strip()))


def _looks_like_card(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    digits = _digits_only(value)
    return 13 <= len(digits) <= 19 and _luhn_ok(digits)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


_PHONE_SHAPE = re.compile(r"^[+()\-\s.\d]+$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T].*)?$")


def _looks_like_phone(value: Any) -> bool:
    """A phone number: digits, and nothing but phone punctuation.

    Requiring the whole string to be phone-shaped stops free text that happens
    to contain a few numbers from being flagged. ISO dates are excluded
    explicitly: ``2024-01-15`` has the same shape as a phone number.
    """
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if _ISO_DATE.match(candidate):
        return False
    if not _PHONE_SHAPE.match(candidate):
        return False
    digits = _digits_only(candidate)
    return 7 <= len(digits) <= 15


def _looks_like_free_text(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 60 and " " in value


_VALUE_PATTERNS: tuple[ValuePattern, ...] = (
    ValuePattern("email", "email", "email", _looks_like_email, {"domain": "example.test"}),
    ValuePattern("ssn", "government-id", "hash", _looks_like_ssn, {"length": 12}),
    ValuePattern("card", "card", "partial_mask", _looks_like_card, {"keep_last": 4}),
    ValuePattern("iban", "financial", "hash", _looks_like_iban, {"length": 12}),
    ValuePattern("ipv4", "network", "preserve_format", _looks_like_ipv4),
    ValuePattern("uuid", "identifier", "hash", _looks_like_uuid, {"length": 12}),
    ValuePattern("phone", "phone", "partial_mask", _looks_like_phone, {"keep_last": 4}),
    ValuePattern("url", "reference", "keep", _looks_like_url, confidence="low"),
    ValuePattern("free-text", "free-text", "keep", _looks_like_free_text),
)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ColumnFinding:
    """One column Masker thinks needs attention."""

    table: str
    column: str
    category: str
    transformer: str
    params: dict[str, Any]
    #: ``name``, ``value`` or ``both``.
    detected_by: str
    confidence: str
    has_rule: bool
    current_transformer: str | None = None
    matches: int = 0
    sampled: int = 0

    @property
    def unmasked(self) -> bool:
        return self.current_transformer is None or self.current_transformer in (
            PASSTHROUGH_TRANSFORMERS
        )

    @property
    def explicit(self) -> bool:
        """``True`` when the rules file says ``keep``.

        That is a reviewed decision rather than an omission, so it does not
        fail ``--strict``. ``verify`` draws exactly the same distinction; the
        two commands must not disagree about whether a column is handled.
        """
        return self.current_transformer in PASSTHROUGH_TRANSFORMERS

    @property
    def label(self) -> str:
        return f"{self.table}.{self.column}"


@dataclass(frozen=True)
class ScanResult:
    """Everything ``masker scan`` reports."""

    findings: tuple[ColumnFinding, ...]
    unruled: tuple[tuple[str, str], ...]
    tables_scanned: int
    columns_scanned: int
    rows_sampled: int

    @property
    def suspected_pii(self) -> tuple[ColumnFinding, ...]:
        return tuple(f for f in self.findings if f.confidence in ("high", "medium"))

    @property
    def unmasked_suspected_pii(self) -> tuple[ColumnFinding, ...]:
        """Suspected PII with no real rule -- what ``--strict`` fails on.

        Categories in :data:`NON_GATING_CATEGORIES` are reported but do not
        fail the gate: free text cannot be masked column-wise, and a URL is
        not personal data on its own.
        """
        return tuple(
            f
            for f in self.suspected_pii
            if f.unmasked and not f.explicit and f.category not in NON_GATING_CATEGORIES
        )

    @property
    def ok(self) -> bool:
        return not self.unmasked_suspected_pii

    def to_dict(self) -> dict[str, Any]:
        """The scan result as plain data, for ``masker scan --json``."""
        return {
            "ok": self.ok,
            "tables_scanned": self.tables_scanned,
            "columns_scanned": self.columns_scanned,
            "rows_sampled": self.rows_sampled,
            "suspected_pii": [
                {
                    "table": finding.table,
                    "column": finding.column,
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "detected_by": finding.detected_by,
                    "suggested_transformer": finding.transformer,
                    "suggested_params": finding.params,
                    "current_transformer": finding.current_transformer,
                    "unmasked": finding.unmasked,
                    "explicit_keep": finding.explicit,
                }
                for finding in self.findings
            ],
            "unmasked_suspected_pii": [finding.label for finding in self.unmasked_suspected_pii],
            "columns_without_rule": [
                {"table": table, "column": column} for table, column in self.unruled
            ],
        }


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def scan_schema(
    engine: Engine,
    schema: ReflectedSchema,
    rules: RulesFile | None = None,
    *,
    sample_size: int = 200,
    tables: Iterable[str] | None = None,
) -> ScanResult:
    """Scan the schema for columns that look like PII."""
    selected = set(tables) if tables is not None else None
    findings: list[ColumnFinding] = []
    unruled: list[tuple[str, str]] = []
    columns_scanned = 0
    tables_scanned = 0
    rows_sampled = 0

    for name in sorted(schema.tables):
        if selected is not None and name not in selected:
            continue
        table = schema.tables[name]
        table_rule = rules.tables.get(name) if rules else None
        if table_rule is not None and table_rule.action in ("skip", "truncate"):
            continue
        tables_scanned += 1
        samples = _sample_columns(engine, table.table, table.column_names, sample_size)
        rows_sampled += len(next(iter(samples.values()), ()))

        for column in table.columns:
            columns_scanned += 1
            column_rule = table_rule.columns.get(column.name) if table_rule else None
            current = column_rule.transformer if column_rule else None
            if current is None:
                unruled.append((name, column.name))

            finding = _finding(name, column, samples.get(column.name) or [], current)
            if finding is not None:
                findings.append(finding)

    return ScanResult(
        findings=tuple(findings),
        unruled=tuple(unruled),
        tables_scanned=tables_scanned,
        columns_scanned=columns_scanned,
        rows_sampled=rows_sampled,
    )


def _sample_columns(
    engine: Engine,
    table: Table,
    column_names: list[str],
    sample_size: int,
) -> dict[str, list[Any]]:
    """Read up to ``sample_size`` rows and group the values by column."""
    samples: dict[str, list[Any]] = {name: [] for name in column_names}
    statement = select(*[table.c[name] for name in column_names]).limit(sample_size)
    try:
        with engine.connect() as conn:
            for row in conn.execute(statement):
                for index, name in enumerate(column_names):
                    value = row[index]
                    if value is not None:
                        samples[name].append(value)
    except SQLAlchemyError as exc:
        raise SchemaError(f"Could not sample table {table.name}: {exc}") from exc
    return samples


def _finding(
    table_name: str,
    column: ColumnInfo,
    values: list[Any],
    current: str | None,
) -> ColumnFinding | None:
    name_match = match_name(column.name)
    value_match, matches = _match_values(values)

    if value_match is not None and (name_match is None or name_match.confidence == "low"):
        confidence = value_match.confidence
        detected_by = "value"
        transformer, params = value_match.transformer, value_match.params
        category = value_match.category
    elif name_match is not None and value_match is not None:
        detected_by = "both"
        confidence = "high"
        transformer, params = name_match.transformer, name_match.params
        category = name_match.category
    elif name_match is not None:
        detected_by = "name"
        confidence = name_match.confidence
        transformer, params = name_match.transformer, name_match.params
        category = name_match.category
    else:
        return None

    return ColumnFinding(
        table=table_name,
        column=column.name,
        category=category,
        transformer=transformer,
        params=dict(params),
        detected_by=detected_by,
        confidence=confidence,
        has_rule=current is not None,
        current_transformer=current,
        matches=matches,
        sampled=len(values),
    )


def _match_values(values: list[Any]) -> tuple[ValuePattern, int] | tuple[None, int]:
    """The strongest value-shape match, with how many samples matched."""
    for pattern in _VALUE_PATTERNS:
        matches = sum(1 for value in values if pattern.check(value))
        if not matches:
            continue
        if matches >= 3 and matches >= len(values) * 0.5:
            return pattern, matches
        if matches >= 1 and len(values) <= 5:
            return pattern, matches
    return None, 0
