"""Key handling: resolution order, weak keys, and the determinism contract."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from masker.errors import KeyError_
from masker.keys import (
    KEY_FILE_ENV,
    MIN_KEY_LENGTH,
    SECRET_KEY_ENV,
    SecretKey,
)

GOOD = "unit-test-key-0123456789abcdef"


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SECRET_KEY_ENV, GOOD)
    key = SecretKey.resolve(env=dict(os.environ))
    assert key.material == GOOD.encode()
    assert key.origin == f"env:{SECRET_KEY_ENV}"


def test_missing_key_is_refused() -> None:
    with pytest.raises(KeyError_, match="refuses to run without one"):
        SecretKey.resolve(env={})


def test_key_file_wins_over_the_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    file_key = tmp_path / "masker.key"
    file_key.write_text(GOOD + "\n", encoding="utf-8")
    monkeypatch.setenv(SECRET_KEY_ENV, "ignored-env-key-0123456789")
    key = SecretKey.resolve(key_file=str(file_key), env=dict(os.environ))
    assert key.material == GOOD.encode()
    assert key.origin == f"file:{file_key}"


def test_key_file_env_var(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    file_key = tmp_path / "masker.key"
    file_key.write_text(GOOD, encoding="utf-8")
    key = SecretKey.resolve(env={KEY_FILE_ENV: str(file_key)})
    assert key.material == GOOD.encode()


def test_key_file_takes_precedence_over_its_env_var(tmp_path: Path) -> None:
    preferred = tmp_path / "preferred.key"
    preferred.write_text("preferred-key-0123456789abcdef", encoding="utf-8")
    fallback = tmp_path / "fallback.key"
    fallback.write_text("fallback-key-0123456789abcdef", encoding="utf-8")
    key = SecretKey.resolve(
        key_file=str(preferred), env={KEY_FILE_ENV: str(fallback), SECRET_KEY_ENV: GOOD}
    )
    assert key.material == b"preferred-key-0123456789abcdef"


def test_missing_key_file(tmp_path: Path) -> None:
    with pytest.raises(KeyError_, match="Key file not found"):
        SecretKey.from_file(tmp_path / "absent.key")


def test_unreadable_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = tmp_path / "locked.key"
    key_file.write_text(GOOD, encoding="utf-8")

    def explode(self: Path, *args: object, **kwargs: object) -> str:
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", explode)
    with pytest.raises(KeyError_, match="Could not read key file"):
        SecretKey.from_file(key_file)


def test_weak_key_is_refused() -> None:
    with pytest.raises(KeyError_, match="too weak"):
        SecretKey.from_text("short", origin="test")


def test_minimum_length_is_accepted_but_flagged_as_weak() -> None:
    key = SecretKey.from_text("x" * MIN_KEY_LENGTH, origin="test")
    assert key.is_weak()
    assert not SecretKey.from_text("y" * 64, origin="test").is_weak()


def test_empty_key_is_refused() -> None:
    with pytest.raises(KeyError_, match="empty"):
        SecretKey(material=b"")


def test_whitespace_is_stripped() -> None:
    assert SecretKey.from_text(f"  {GOOD}  \n", origin="test").material == GOOD.encode()


def test_ephemeral_key_is_marked_and_unique() -> None:
    first, second = SecretKey.ephemeral_key(), SecretKey.ephemeral_key()
    assert first.ephemeral
    assert second.ephemeral
    assert first.material != second.material


def test_ephemeral_flag_overrides_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SECRET_KEY_ENV, GOOD)
    key = SecretKey.resolve(ephemeral=True, env=dict(os.environ))
    assert key.ephemeral


def test_digest_is_namespaced_by_its_parts() -> None:
    key = SecretKey.from_text(GOOD, origin="test")
    assert key.digest("a", "b") != key.digest("a", "c")
    assert key.digest("a", "b") != key.digest("a|b")


def test_digest_is_stable_across_instances() -> None:
    first = SecretKey.from_text(GOOD, origin="a")
    second = SecretKey.from_text(GOOD, origin="b")
    assert first.digest("x") == second.digest("x")
    assert first.int_digest("x") == second.int_digest("x")
    assert first.hex_digest("x", length=8) == second.hex_digest("x", length=8)


def test_hex_digest_honours_its_length() -> None:
    key = SecretKey.from_text(GOOD, origin="test")
    assert len(key.hex_digest("value", length=16)) == 16
    assert len(key.hex_digest("value", length=0)) == 1


def test_stream_is_reproducible() -> None:
    key = SecretKey.from_text(GOOD, origin="test")
    first = [key.stream("a").random() for _ in range(3)]
    second = [key.stream("a").random() for _ in range(3)]
    assert first == second
