"""Exception hierarchy for Masker.

Every error a user can act on derives from :class:`MaskerError` and carries an
optional ``hint`` with the next thing to try. The CLI formats these uniformly
and always scrubs credentials before printing (see :mod:`masker.connect`).
"""

from __future__ import annotations

__all__ = [
    "ConfigError",
    "KeyError_",
    "LeakDetected",
    "MaskerError",
    "SafetyError",
    "SameDatabaseError",
    "SchemaError",
    "TargetNotEmptyError",
    "TransformerError",
    "UniquenessError",
    "format_error",
]


class MaskerError(Exception):
    """Base class for every error Masker raises on purpose."""

    #: Short machine-readable code, useful in JSON reports and tests.
    code = "masker-error"

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\n  hint: {self.hint}"
        return self.message


class ConfigError(MaskerError):
    """The rules file is missing, unparsable, or semantically invalid."""

    code = "config-error"


class SchemaError(MaskerError):
    """The database schema could not be reflected or does not match the rules."""

    code = "schema-error"


class KeyError_(MaskerError):
    """The masking key is missing, unusable, or too weak.

    Named with a trailing underscore so it never shadows the builtin
    :class:`KeyError` at import sites.
    """

    code = "key-error"


class SafetyError(MaskerError):
    """A safety guard refused to continue."""

    code = "safety-error"


class SameDatabaseError(SafetyError):
    """Source and target resolve to the same database."""

    code = "same-database"


class TargetNotEmptyError(SafetyError):
    """The target database already contains data."""

    code = "target-not-empty"


class TransformerError(MaskerError):
    """A transformer could not produce a valid value for a row."""

    code = "transformer-error"


class UniquenessError(TransformerError):
    """A transformer could not produce a unique value for a unique column."""

    code = "uniqueness-error"


class LeakDetected(MaskerError):
    """Verification found original values in the anonymized target."""

    code = "leak-detected"


def format_error(err: BaseException) -> str:
    """Render an exception for the terminal, hint included when present."""
    if isinstance(err, MaskerError):
        return str(err)
    return f"{type(err).__name__}: {err}"
