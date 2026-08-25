#!/usr/bin/env python3
"""Generate `vectors/technocore-signer-vectors.json` from the implementation.

Written to be consumed by *other* implementations — the file is language-neutral, every string is
escaped rather than literal, and each case carries the reason it exists so a reader can tell a
load-bearing vector from a decorative one.

It is generated rather than hand-maintained, and `tests/test_vectors.py` asserts the committed file
still matches what the code produces. A vector file that drifts from its implementation is worse
than none: it certifies the wrong thing while looking authoritative.

    ./bin/export_vectors.py            # regenerate
    ./bin/export_vectors.py --check    # exit 1 if the committed file is stale
"""

from __future__ import annotations

import json
import pathlib
import sys

from technocore_sdk.didkey import Identity, message_canonical, note_canonical
from technocore_sdk.sweep import sweep

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "vectors" / "technocore-signer-vectors.json"

# A fixed seed so every value below is reproducible byte-for-byte. Ed25519 signing is
# deterministic, so an implementation that agrees on these agrees everywhere.
SEED_HEX = "07" * 32

SWEEP_CASES = [
    ("\u200b", "zero-width space", "Cf. The common one: pasted from a web page, renders as nothing."),
    ("\u202e", "right-to-left override", "Cf. Trojan Source. Can make stored text read differently from the source."),
    ("\u00ad", "soft hyphen", "Cf. Survives copy-paste from PDFs and word processors."),
    ("\n", "newline", "Cc. The storage invariant is one record per line."),
    ("\r", "carriage return", "Cc. Arrives with anything that has touched Windows."),
    ("\t", "tab", "Cc."),
    ("\u2028", "line separator", "Zl."),
    ("\u2029", "paragraph separator", "Zp."),
    ("\u200d", "zero-width joiner", "Cf. Splits or joins emoji sequences."),
    ("\u2060", "word joiner", "Cf."),
    ("\ufeff", "BOM / zero-width no-break space", "Cf. Leads many files."),
    ("\u0085", "next line", "Cc. A C1 control, easy to miss when only C0 is handled."),
    ("\U000e0041", "Unicode tag character", "Cf. Invisible and can carry a payload."),
]

# Not swept: proof that the rule is by Unicode category, not a blocklist of odd characters.
SURVIVES = [
    ("\u00a0", "no-break space", "Zs, not in the swept set. Must survive unchanged."),
    ("\U0001f680", "emoji", "So. Must survive unchanged."),
    ("\u00e9", "e-acute", "Ll. Must survive unchanged."),
]


def build() -> dict:
    identity = Identity.from_seed(bytes.fromhex(SEED_HEX))

    sweep_vectors = []
    for char, name, why in SWEEP_CASES:
        raw = f"a{char}b"
        sweep_vectors.append({
            "name": f"sweep: {name}",
            "input": raw,
            "expected": sweep(raw),
            "why": why,
        })
    for char, name, why in SURVIVES:
        raw = f"a{char}b"
        sweep_vectors.append({
            "name": f"survives: {name}",
            "input": raw,
            "expected": sweep(raw),
            "why": why,
        })
    sweep_vectors += [
        {"name": "trims the ends", "input": "  hi  ", "expected": sweep("  hi  "),
         "why": "Trim happens after replacement, so swept characters at the ends disappear too."},
        {"name": "trims swept characters at the ends",
         "input": "\u200bhi\u200b", "expected": sweep("\u200bhi\u200b"),
         "why": "The failure that produces a 403 nobody can explain: the client signs the "
                "untrimmed text and the server stores the trimmed text."},
        {"name": "keeps interior runs", "input": "a   b", "expected": sweep("a   b"),
         "why": "Interior whitespace is not collapsed. Only invisibles become spaces."},
        {"name": "consecutive invisibles each become a space",
         "input": f"a{chr(0x200b)}{chr(0x200b)}b", "expected": sweep("a\u200b\u200bb"),
         "why": "One space per character, not one per run."},
    ]

    message_vectors = []
    for room, nonce, text in [
        ("lobby", 1, "hello world"),
        ("lobby", 1, "a\u200bb"),
        ("meta", 42, "  padded  "),
        ("mb-p-abc", 7, "mailbox line"),
        ("lobby", 999999999999999, "large nonce"),
    ]:
        canonical = message_canonical(room, nonce, text)
        message_vectors.append({
            "room": room, "nonce": nonce, "text_before_sweep": text,
            "text_after_sweep": sweep(text),
            "canonical": canonical,
            "signature": identity.sign(canonical),
        })

    note_vectors = []
    for namespace, key, nonce, value in [
        ("room-owners", "d-demo", 3, identity.did),
        ("room-allow", "d-demo", 4, identity.did),
    ]:
        canonical = note_canonical(namespace, key, nonce, value)
        note_vectors.append({
            "namespace": namespace, "key": key, "nonce": nonce, "value": value,
            "canonical": canonical,
            "signature": identity.sign(canonical),
        })

    return {
        "schema": "technocore-signer-vectors-v1",
        "generated_by": "https://github.com/stupeterwilliams-ui/technocore-sdk",
        "license": "Apache-2.0",
        "purpose": (
            "Fixed vectors for the three things a Technocore signer must get exactly right: the "
            "single-line sweep, the canonical string, and the resulting Ed25519 signature. "
            "Contributed for use in any implementation."
        ),
        "identity": {
            "seed_hex": SEED_HEX,
            "did": identity.did,
            "note": "Ed25519 signing is deterministic, so these signatures are exact byte "
                    "strings. An implementation that reproduces them agrees with this one "
                    "everywhere, not just on these inputs.",
        },
        "sweep": {
            "rule": "Replace every character whose Unicode general category is Cc, Cf, Cs, Co, Zl "
                    "or Zp with a space (U+0020), then strip leading and trailing whitespace.",
            "categories": ["Cc", "Cf", "Cs", "Co", "Zl", "Zp"],
            "vectors": sweep_vectors,
        },
        "canonical_strings": {
            "message": "<room>|<nonce>|<text after sweep>",
            "note": "<namespace>|<key>|<nonce>|<value after sweep>",
            "critical": "The signature covers the text AFTER the sweep — the bytes the server "
                        "stores. Signing the raw input returns 403 for any text containing an "
                        "invisible character, and the cause is not visible in the input.",
            "message_vectors": message_vectors,
            "note_vectors": note_vectors,
        },
        "nonce_lifecycle": {
            "rule": "A nonce must be strictly greater than the last nonce that key used in that "
                    "room. Scope is (key, room), not global.",
            "cases": [
                {"name": "strictly increases within a scope",
                 "assert": "Allocating repeatedly for one scope yields strictly increasing values "
                           "with no repeats, including within a single millisecond.",
                 "why": "A millisecond clock alone repeats under a fast loop and the second write "
                        "is refused."},
                {"name": "survives a restart",
                 "assert": "After reloading persisted state, the next value exceeds every value "
                           "issued before the restart.",
                 "why": "The failure that actually bites in production: an in-memory counter "
                        "restarts low and every write is refused until it climbs past its own "
                        "history. Nothing in the manual warns about it."},
                {"name": "scopes are independent",
                 "assert": "A fresh scope is not held back by another scope's counter."},
                {"name": "corrupt persisted state does not wedge the client",
                 "assert": "An unreadable store falls back to a clock floor rather than raising.",
                 "why": "A corrupt file should cost you a nonce gap, not the ability to write."},
                {"name": "one signer per key",
                 "assert": "Two processes signing with one key against one room interleave and "
                           "refuse each other. No library can fix this; it belongs in the docs.",
                 "why": "Discovered the hard way is expensive: both signers start failing at once."},
            ],
        },
    }


def main(argv: list[str]) -> int:
    payload = build()
    rendered = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text() != rendered:
            print(f"{OUT.relative_to(ROOT)} is stale — run ./bin/export_vectors.py")
            return 1
        print(f"{OUT.relative_to(ROOT)} matches the implementation")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    counts = (len(payload["sweep"]["vectors"]),
              len(payload["canonical_strings"]["message_vectors"]),
              len(payload["canonical_strings"]["note_vectors"]),
              len(payload["nonce_lifecycle"]["cases"]))
    print(f"wrote {OUT.relative_to(ROOT)}: {counts[0]} sweep, {counts[1]} message, "
          f"{counts[2]} note, {counts[3]} nonce cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
