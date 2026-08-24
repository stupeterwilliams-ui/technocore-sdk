"""did:key derivation, canonical strings, and cross-implementation parity.

The parity assertions are the point of this file. A signer that agrees with itself but not with
the server is broken in a way no self-consistent test will ever catch, so the fixed vectors below
are pinned against the reference implementation rather than against our own output.
"""

import os
import shutil
import subprocess

import pytest

from technocore.didkey import (
    Identity,
    b58decode,
    b58encode,
    b64url,
    fingerprint,
    message_canonical,
    note_canonical,
    public_key_from_did,
    verify,
)

# 32 bytes of 0x07 — the same fixed seed used by the reference vectors.
SEED = bytes([7]) * 32
EXPECTED_DID = "did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z"
# Ed25519 is deterministic, so this is an exact byte string, not an example.
EXPECTED_SIG = (
    "fVc7wd0O78uyyk90jD7bkVmLIPeQWyrHQ2Qf9HVGKQzrImnWDUkFdRu8EvO7oiYyM7Bq90Wp8-KufIojB5MBCA"
)
CANONICAL = "lobby|1|hello world"


def test_did_from_fixed_seed():
    assert Identity.from_seed(SEED).did == EXPECTED_DID


def test_did_length_is_56():
    assert len(EXPECTED_DID) == 56


def test_signature_is_byte_identical_to_the_reference():
    assert Identity.from_seed(SEED).sign(CANONICAL) == EXPECTED_SIG


def test_signature_shape():
    sig = Identity.from_seed(SEED).sign(CANONICAL)
    assert len(sig) == 86
    assert "=" not in sig  # unpadded
    assert all(c.isalnum() or c in "-_" for c in sig)  # base64url alphabet


def test_verify_roundtrip_and_rejections():
    identity = Identity.from_seed(SEED)
    sig = identity.sign(CANONICAL)
    assert verify(identity.did, sig, CANONICAL)
    assert not verify(identity.did, sig, CANONICAL + "x")           # tampered text
    assert not verify(identity.did, sig, "meta|1|hello world")      # wrong room
    assert not verify(identity.did, sig, "lobby|2|hello world")     # different nonce
    assert not verify(Identity.generate().did, sig, CANONICAL)      # wrong key


def test_verify_is_false_not_raising_on_garbage():
    assert not verify("did:key:znonsense", "not-a-signature", CANONICAL)


def test_fingerprint_is_16_hex():
    fp = fingerprint(EXPECTED_DID)
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_base58_roundtrip_preserves_leading_zeros():
    for data in (b"\x00\x00\x01\x02", b"\xed\x01" + bytes(32), os.urandom(20)):
        assert b58decode(b58encode(data)) == data


def test_public_key_recovered_from_did():
    identity = Identity.from_seed(SEED)
    recovered = public_key_from_did(identity.did)
    # Verifying through the recovered key is the real assertion.
    from technocore.didkey import b64url_decode

    recovered.verify(b64url_decode(identity.sign(CANONICAL)), CANONICAL.encode())


def test_public_key_from_did_rejects_non_did_key():
    with pytest.raises(ValueError):
        public_key_from_did("https://example.com/key")


def test_canonical_strings_cover_the_swept_text():
    # The canonical string must carry what gets STORED, not what was typed.
    assert message_canonical("lobby", 1, "a\u200bb") == "lobby|1|a b"
    assert note_canonical("room-owners", "d-x", 9, " v ") == "room-owners|d-x|9|v"


def test_seed_roundtrip():
    assert Identity.from_seed(SEED).seed() == SEED


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError):
        Identity.from_seed(b"short")


# ---------------------------------------------------------------------------
# Live parity against the upstream reference signer, when a checkout is present.
# ---------------------------------------------------------------------------

UPSTREAM = os.path.expanduser("~/Projects/technocore-conformance/upstream")
SIGNER = os.path.join(UPSTREAM, "scripts", "sign.py")


@pytest.mark.skipif(
    not os.path.exists(SIGNER) or shutil.which("uv") is None,
    reason="upstream checkout or uv not available",
)
@pytest.mark.parametrize(
    "room, nonce, text",
    [
        ("lobby", 1, "hello world"),
        ("meta", 42, "a message with  interior  spaces"),
        ("lobby", 999999, "unicode: café — ok"),
        ("mb-p-abc", 7, "mailbox line"),
    ],
)
def test_parity_with_reference_signer(room, nonce, text):
    """Our signature must equal the one `scripts/sign.py` produces for the same inputs."""
    result = subprocess.run(
        ["uv", "run", SIGNER, "say", "--seed", SEED.hex(), room, str(nonce), text],
        capture_output=True,
        text=True,
        check=False,
        cwd=UPSTREAM,
        timeout=180,
        env={**os.environ, "UV_CACHE_DIR": os.path.join(UPSTREAM, ".uvcache")},
    )
    assert result.returncode == 0, result.stderr
    reference_did, reference_sig = result.stdout.split()[:2]

    identity = Identity.from_seed(SEED)
    assert identity.did == reference_did
    assert identity.sign(message_canonical(room, nonce, text)) == reference_sig


@pytest.mark.skipif(
    not os.path.exists(SIGNER) or shutil.which("uv") is None,
    reason="upstream checkout or uv not available",
)
def test_note_parity_with_reference_signer():
    result = subprocess.run(
        ["uv", "run", SIGNER, "set", "--seed", SEED.hex(), "room-owners", "d-demo", "3",
         "did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z"],
        capture_output=True,
        text=True,
        check=False,
        cwd=UPSTREAM,
        timeout=180,
        env={**os.environ, "UV_CACHE_DIR": os.path.join(UPSTREAM, ".uvcache")},
    )
    assert result.returncode == 0, result.stderr
    _, reference_sig = result.stdout.split()[:2]

    canonical = note_canonical(
        "room-owners", "d-demo", 3, "did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z"
    )
    assert Identity.from_seed(SEED).sign(canonical) == reference_sig


def test_b64url_is_unpadded():
    assert b64url(b"\x00") == "AA"
