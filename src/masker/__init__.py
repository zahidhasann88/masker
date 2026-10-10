"""Masker - deterministic, schema-aware database anonymization.

Masker reads from a production database and writes an anonymized copy to a
separate target database. It never modifies the source.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
