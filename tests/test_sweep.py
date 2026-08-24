"""Fixed vectors for the sweep.

These are the cases that break a correct-looking client silently. Each one is a character that
renders as nothing, or as something other than what it is, and every one of them changes the bytes
the server stores — and therefore the bytes a signature must cover.

Every character here is written as an escape sequence on purpose. A test file about invisible
characters that contains literal invisible characters is unreadable in a diff and is one careless
copy-paste away from testing something other than what it claims.
"""

import pytest

from technocore.sweep import MAX_MESSAGE_CHARS, is_swept, sweep, swept_for_write

ZWSP = "\u200b"  # zero-width space (Cf)
RLO = "\u202e"  # right-to-left override — the Trojan Source character (Cf)
SHY = "\u00ad"  # soft hyphen (Cf)
LSEP = "\u2028"  # line separator (Zl)
PSEP = "\u2029"  # paragraph separator (Zp)
ZWJ = "\u200d"  # zero-width joiner (Cf)
WJ = "\u2060"  # word joiner (Cf)
BOM = "\ufeff"  # zero-width no-break space (Cf)
C1 = "\u0085"  # next line, a C1 control (Cc)
TAG_A = "\U000e0041"  # Unicode tag character (Cf) — invisible, and carries data
NBSP = "\u00a0"  # no-break space is Zs, NOT in the swept set: it must survive


@pytest.mark.parametrize(
    "name, raw, expected",
    [
        ("zero-width space", f"a{ZWSP}b", "a b"),
        ("bidi override (Trojan Source)", f"a{RLO}b", "a b"),
        ("soft hyphen", f"a{SHY}b", "a b"),
        ("newline", "a\nb", "a b"),
        ("carriage return", "a\rb", "a b"),
        ("tab", "a\tb", "a b"),
        ("U+2028 line separator", f"a{LSEP}b", "a b"),
        ("U+2029 paragraph separator", f"a{PSEP}b", "a b"),
        ("Unicode tag character", f"a{TAG_A}b", "a b"),
        ("zero-width joiner", f"a{ZWJ}b", "a b"),
        ("word joiner", f"a{WJ}b", "a b"),
        ("BOM / zero-width no-break space", f"a{BOM}b", "a b"),
        ("C1 control", f"a{C1}b", "a b"),
        ("trims the ends", "  hi  ", "hi"),
        ("trims swept characters at the ends too", f"{ZWSP}hi{ZWSP}", "hi"),
        ("keeps interior runs", "a   b", "a   b"),
        ("NBSP is Zs and survives", f"a{NBSP}b", f"a{NBSP}b"),
        ("plain text is untouched", "hello world", "hello world"),
        ("emoji survives", "ship it \U0001f680", "ship it \U0001f680"),
        ("consecutive invisibles each become a space", f"a{ZWSP}{ZWSP}b", "a  b"),
    ],
)
def test_sweep_vectors(name, raw, expected):
    assert sweep(raw) == expected, name


def test_is_swept():
    assert is_swept("clean text")
    assert not is_swept(f"a{ZWSP}b")
    assert not is_swept(" leading")


def test_all_invisible_is_refused_before_signing():
    # The server refuses this write. Learning it here beats learning it from a 4xx after
    # burning a nonce.
    with pytest.raises(ValueError, match="nothing visible"):
        swept_for_write(ZWSP + ZWSP, MAX_MESSAGE_CHARS)


def test_over_cap_is_refused():
    with pytest.raises(ValueError, match="over the 4096-character cap"):
        swept_for_write("a" * 4097, MAX_MESSAGE_CHARS)


def test_cap_is_measured_after_the_sweep():
    # 4096 visible characters plus invisibles that collapse away at the ends still fits.
    assert len(swept_for_write(ZWSP + "a" * 4096 + ZWSP, MAX_MESSAGE_CHARS)) == 4096
