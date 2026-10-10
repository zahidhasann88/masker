"""Masker's transformers.

Importing this package registers every built-in transformer in
:data:`~masker.transformers.registry.REGISTRY`.
"""

from __future__ import annotations

from typing import Any

from masker.transformers import (  # noqa: F401  (import side effect: registration)
    constant,
    date_shift,
    email,
    fake,
    hash,
    keep,
    null,
    number_noise,
    partial_mask,
    preserve_format,
    redact,
    regex_replace,
    shuffle,
)
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import REGISTRY, register

__all__ = [
    "REGISTRY",
    "BaseParams",
    "BaseTransformer",
    "ColumnContext",
    "build",
    "names",
    "register",
]


def build(name: str, params: dict[str, Any] | None, ctx: ColumnContext) -> BaseTransformer[Any]:
    """Instantiate a transformer by registry name."""
    return REGISTRY.build(name, params, ctx)


def names() -> list[str]:
    """All registered transformer names, sorted."""
    return REGISTRY.names()
