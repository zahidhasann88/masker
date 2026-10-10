"""``email`` -- same shape, safe domain, fake local part.

```yaml
columns:
  email:       {transformer: email}
  work_email:  {transformer: email, params: {domain: example.test, style: hash}}
```

``"jane.doe+news@corp.example"`` becomes something like
``"bravo.foxtrot4821+echo@example.test"``:

* the dot and ``+tag`` structure of the local part survives;
* a short keyed digit suffix keeps the local part unique enough to satisfy a
  UNIQUE constraint (a word alone would repeat after a few dozen rows);
* the domain is replaced by a reserved, unroutable one, so no real mailbox can
  ever receive mail from a masked dump.
"""

from __future__ import annotations

import random
from typing import Any, Literal

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["EmailParams", "EmailTransformer"]

#: Fixed word list on purpose: Faker's word list changes between versions, and
#: email output should not.
_WORDS = [
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
    "amber",
    "birch",
    "cedar",
    "dune",
    "ember",
    "fern",
    "glade",
    "harbor",
    "ivory",
    "jasmine",
]


class EmailParams(BaseParams):
    domain: str = "example.test"
    style: Literal["words", "hash"] = "words"
    #: Digits appended to the local part for entropy. Set to 0 to disable.
    #:
    #: This is what keeps a UNIQUE email column satisfiable: the word list
    #: gives 35 options, so 4 digits would only reach ~350k distinct local
    #: parts and a 100k-row table would need thousands of uniqueness retries.
    #: 8 digits reaches ~3.5 billion, which makes collisions rare into the
    #: millions of rows. Lower it if you prefer shorter addresses and your
    #: table is small.
    suffix_digits: int = 8
    #: Keep the original domain instead of replacing it. Off by default: a real
    #: domain in a shared dump is itself a disclosure.
    keep_domain: bool = False


@register
class EmailTransformer(BaseTransformer[EmailParams]):
    name = "email"
    summary = "Replace the local part, keep the structure, use a safe domain."
    params_model = EmailParams

    def _apply(self, value: Any, attempt: int) -> Any:
        text = str(self.require_not_null(value))
        local, _, domain = text.rpartition("@")
        if not local:
            local, domain = text, ""

        base, separator, tag = local.partition("+")
        rng = self.ctx.rng(_stable(value), attempt)

        if self.params.style == "hash":
            new_base = self.ctx.hex_digest(text, attempt, length=12)
        else:
            new_base = self._words(rng, base) + self._suffix(rng)
        new_local = f"{new_base}{separator}{self._words(rng, tag)}" if tag else new_base

        new_domain = domain if self.params.keep_domain and domain else self.params.domain
        return f"{new_local}@{new_domain}" if new_domain else new_local

    def _words(self, rng: random.Random, template: str) -> str:
        """Build a local part with the same dot structure as ``template``."""
        parts = template.split(".") if template else [""]
        return ".".join(rng.choice(_WORDS) for _ in parts)

    def _suffix(self, rng: random.Random) -> str:
        digits = max(0, self.params.suffix_digits)
        if not digits:
            return ""
        return "".join(rng.choice("0123456789") for _ in range(digits))


def _stable(value: Any) -> str:
    return value if isinstance(value, str) else repr(value)
