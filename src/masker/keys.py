"""Key material and the deterministic randomness that derives from it.

Masker's core promise: ``HMAC(secret_key, "table|column|original_value")``
drives every transformation. The same input value therefore always maps to the
same output value, within a run and across runs, as long as the key is the
same. That is what keeps joins, foreign keys and duplicate values intact.

The key is never read from the rules file. It comes from, in order:

1. ``--key-file``
2. ``$MASKER_KEY_FILE``
3. ``$MASKER_SECRET_KEY``

``--ephemeral-key`` generates a throwaway key instead, which makes the run
non-reproducible by design.
"""

from __future__ import annotations

import hmac
import os
import random
import secrets
import struct
from dataclasses import dataclass, field
from pathlib import Path

from masker.errors import KeyError_

__all__ = [
    "EPHEMERAL_WARNING",
    "KEY_FILE_ENV",
    "MIN_KEY_LENGTH",
    "RECOMMENDED_KEY_LENGTH",
    "SECRET_KEY_ENV",
    "SecretKey",
]

SECRET_KEY_ENV = "MASKER_SECRET_KEY"
KEY_FILE_ENV = "MASKER_KEY_FILE"

#: Below this many characters the key is rejected outright.
MIN_KEY_LENGTH = 12
#: Below this many characters the key is accepted but a warning is printed.
RECOMMENDED_KEY_LENGTH = 32

EPHEMERAL_WARNING = (
    "Using an EPHEMERAL key. Output is NOT reproducible: re-running against the "
    "same source will produce different masked values, and joins with previously "
    "masked data will not line up. Use --key-file or ${key_env} for repeatable runs."
)


@dataclass(frozen=True, slots=True)
class SecretKey:
    """The masking key plus the deterministic primitives derived from it."""

    material: bytes = field(repr=False)
    #: ``True`` when the key was generated for this run only.
    ephemeral: bool = False
    #: Where the key came from, safe to print (never contains the key itself).
    origin: str = "<unknown>"

    def __post_init__(self) -> None:
        if not self.material:
            raise KeyError_("The masking key is empty.")

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_text(cls, text: str, *, origin: str) -> SecretKey:
        """Build a key from a passphrase. Surrounding whitespace is stripped."""
        material = text.strip().encode("utf-8")
        if len(material) < MIN_KEY_LENGTH:
            raise KeyError_(
                f"The masking key is too weak ({len(material)} characters, "
                f"minimum {MIN_KEY_LENGTH}).",
                hint=(
                    "Generate one with: "
                    'python -c "import secrets; print(secrets.token_urlsafe(48))"'
                ),
            )
        return cls(material=material, origin=origin)

    @classmethod
    def from_file(cls, path: str | Path) -> SecretKey:
        file_path = Path(path)
        if not file_path.is_file():
            raise KeyError_(
                f"Key file not found: {file_path}",
                hint=(
                    "Create one with: python -c "
                    '"import secrets; print(secrets.token_urlsafe(48))" > masker.key'
                ),
            )
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise KeyError_(f"Could not read key file {file_path}: {exc}") from exc
        return cls.from_text(text, origin=f"file:{file_path}")

    @classmethod
    def ephemeral_key(cls) -> SecretKey:
        return cls(
            material=secrets.token_bytes(48),
            ephemeral=True,
            origin="ephemeral (generated for this run)",
        )

    @classmethod
    def resolve(
        cls,
        *,
        key_file: str | None = None,
        ephemeral: bool = False,
        env: dict[str, str] | None = None,
    ) -> SecretKey:
        """Locate the key using the documented precedence rules."""
        environment = os.environ if env is None else env

        if ephemeral:
            return cls.ephemeral_key()

        if key_file:
            return cls.from_file(key_file)

        env_key_file = environment.get(KEY_FILE_ENV)
        if env_key_file:
            return cls.from_file(env_key_file)

        env_key = environment.get(SECRET_KEY_ENV)
        if env_key:
            return cls.from_text(env_key, origin=f"env:{SECRET_KEY_ENV}")

        raise KeyError_(
            "No masking key found. Masker refuses to run without one.",
            hint=(
                f"Set {SECRET_KEY_ENV}=<passphrase>, point {KEY_FILE_ENV} or --key-file at a "
                "key file, or pass --ephemeral-key for a throwaway key."
            ),
        )

    # ------------------------------------------------------------------ #
    # Derived randomness
    # ------------------------------------------------------------------ #
    def digest(self, *parts: str | int | bytes) -> bytes:
        """``HMAC(key, parts)`` -- the root of all determinism.

        Each part is length-prefixed before being fed to the HMAC. A plain
        separator would make the encoding ambiguous: ``("a", "b")`` and
        ``("a|b",)`` would hash identically, so a value containing the
        separator could collide with a different (column, value) pair.
        """
        mac = hmac.new(self.material, digestmod="sha256")
        for part in parts:
            raw = part.encode("utf-8") if isinstance(part, str) else _as_bytes(part)
            mac.update(len(raw).to_bytes(4, "big"))
            mac.update(raw)
        return mac.digest()

    def int_digest(self, *parts: str | int | bytes, n_bytes: int = 8) -> int:
        """The digest as a non-negative integer, truncated to ``n_bytes``."""
        if not 1 <= n_bytes <= 32:
            raise ValueError("n_bytes must be between 1 and 32")
        raw = self.digest(*parts)[:n_bytes]
        return int.from_bytes(raw, "big")

    def stream(self, *parts: str | int | bytes) -> random.Random:
        """A :class:`random.Random` seeded from the digest of ``parts``.

        Python's Mersenne Twister seeding from an integer is stable across
        versions and platforms, so this stream is reproducible everywhere.
        """
        seed = struct.unpack(">Q", self.digest(*parts)[:8])[0]
        return random.Random(seed)

    def hex_digest(self, *parts: str | int | bytes, length: int = 12) -> str:
        """Hex-encoded digest truncated to ``length`` characters."""
        return self.digest(*parts).hex()[: max(1, length)]

    # ------------------------------------------------------------------ #
    def is_weak(self) -> bool:
        return len(self.material) < RECOMMENDED_KEY_LENGTH


def _as_bytes(part: int | bytes) -> bytes:
    return str(part).encode("utf-8") if isinstance(part, int) else part
