"""The single-line sweep.

Every write to technocore-chat passes through this before storage: each character whose Unicode
category is Cc, Cf, Cs, Co, Zl or Zp becomes a space, then the ends are trimmed.

This matters far more than it looks. The signed lane's canonical string covers the text *after*
the sweep — the bytes that actually get stored — so a client that signs its raw input produces a
signature over something the server never stores, and gets a 403 it cannot debug. One zero-width
space pasted into a message is enough.

Signing the swept text is not a workaround. It is what makes a stored record re-verifiable later.
"""

from __future__ import annotations

import unicodedata

# Cs (surrogates) and Co (private use) cannot appear in well-formed decoded text in most inputs,
# but they are in the server's set, so they are in ours. Parity is the whole point of this module.
_SWEPT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


def sweep(text: str) -> str:
    """Return *text* as the server will store it.

    >>> sweep("a\\u200bb")
    'a b'
    >>> sweep("  x  ")
    'x'
    """
    return "".join(
        " " if unicodedata.category(ch) in _SWEPT_CATEGORIES else ch for ch in text
    ).strip()


def is_swept(text: str) -> bool:
    """True if *text* would survive the sweep unchanged — i.e. it is safe to sign as-is."""
    return sweep(text) == text


MAX_MESSAGE_CHARS = 4096
MAX_NOTE_CHARS = 8192


def swept_for_write(text: str, limit: int) -> str:
    """Sweep *text* and refuse what the server would refuse anyway.

    Raising here rather than letting the write 4xx means the caller learns *why* at the point it
    can still do something about it. Mirrors the reference signer's behaviour.
    """
    cleaned = sweep(text)
    if not cleaned:
        raise ValueError(
            "nothing visible would be left after the single-line sweep — the server refuses "
            "that write, so there is nothing worth signing"
        )
    if len(cleaned) > limit:
        raise ValueError(
            f"{len(cleaned)} characters after the sweep, over the {limit}-character cap — split it"
        )
    return cleaned
