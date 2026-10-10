"""The transformer registry singleton.

Lives in its own module so transformer modules can import it without creating
an import cycle with :mod:`masker.transformers`.
"""

from __future__ import annotations

from typing import Any

from masker.transformers.base import BaseTransformer, TransformerRegistry

__all__ = ["REGISTRY", "register"]

REGISTRY = TransformerRegistry()


def register(cls: type[BaseTransformer[Any]]) -> type[BaseTransformer[Any]]:
    """Class decorator adding a transformer to the global registry."""
    return REGISTRY.register(cls)
