"""The exported vector file must match the implementation.

A vector file that drifts from its code is worse than none: it certifies the wrong thing while
looking authoritative, and anyone who adopts it inherits a bug they cannot see.
"""

import json
import pathlib
import subprocess
import sys

import pytest

from technocore_sdk.didkey import Identity, verify
from technocore_sdk.sweep import sweep

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors" / "technocore-signer-vectors.json"

pytestmark = pytest.mark.skipif(not VECTORS.exists(), reason="vectors not generated yet")


@pytest.fixture(scope="module")
def data():
    return json.loads(VECTORS.read_text())


def test_committed_file_is_not_stale():
    result = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "export_vectors.py"), "--check"],
        capture_output=True, text=True, check=False, cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_sweep_vectors_match_the_implementation(data):
    for case in data["sweep"]["vectors"]:
        assert sweep(case["input"]) == case["expected"], case["name"]


def test_message_signatures_verify(data):
    identity = Identity.from_seed(bytes.fromhex(data["identity"]["seed_hex"]))
    assert identity.did == data["identity"]["did"]
    for case in data["canonical_strings"]["message_vectors"]:
        expected = f"{case['room']}|{case['nonce']}|{case['text_after_sweep']}"
        assert case["canonical"] == expected
        assert sweep(case["text_before_sweep"]) == case["text_after_sweep"]
        assert verify(identity.did, case["signature"], case["canonical"]), case["canonical"]


def test_note_signatures_verify(data):
    identity = Identity.from_seed(bytes.fromhex(data["identity"]["seed_hex"]))
    for case in data["canonical_strings"]["note_vectors"]:
        expected = f"{case['namespace']}|{case['key']}|{case['nonce']}|{case['value']}"
        assert case["canonical"] == expected
        assert verify(identity.did, case["signature"], case["canonical"])


def test_file_is_ascii_escaped(data):
    """Every invisible character must be an escape, so the file survives copy-paste and review."""
    raw = VECTORS.read_text()
    assert raw.isascii(), "vector file must be ASCII-escaped or the vectors can be mangled in transit"
