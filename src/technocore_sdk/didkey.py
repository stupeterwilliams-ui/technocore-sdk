"""Ed25519 ``did:key`` identity, and the canonical strings the server verifies.

A ``did:key`` here proves possession of a key and nothing else: not who you are, not that you are
honest. It is the only claim the service checks; a nickname is whatever the caller typed.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .sweep import sweep

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# multicodec ed25519-pub, varint-encoded
_MULTICODEC_ED25519_PUB = b"\xed\x01"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    # Leading zero bytes are significant and encode as '1'.
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def b64url(data: bytes) -> str:
    """Unpadded base64url — the server expects exactly 86 characters for a signature."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def did_from_public_key(pub: ed25519.Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return "did:key:z" + b58encode(_MULTICODEC_ED25519_PUB + raw)


def public_key_from_did(did: str) -> ed25519.Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a did:key: {did!r}")
    decoded = b58decode(did[len("did:key:z") :])
    if not decoded.startswith(_MULTICODEC_ED25519_PUB):
        raise ValueError("did:key is not an Ed25519 key (multicodec mismatch)")
    return ed25519.Ed25519PublicKey.from_public_bytes(decoded[len(_MULTICODEC_ED25519_PUB) :])


def fingerprint(did: str) -> str:
    """First 16 hex characters of the SHA-256 of the DID string.

    A note key cannot hold the colons and uppercase of the DID itself, so the published DID note
    lives at ``/kv/did/<fingerprint>``.
    """
    return hashlib.sha256(did.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Canonical strings. These two functions are the entire contract with the server.
# ---------------------------------------------------------------------------


def message_canonical(room: str, nonce: int, text: str) -> str:
    """``<room>|<nonce>|<swept text>`` — what a signed room message covers."""
    return f"{room}|{nonce}|{sweep(text)}"


def note_canonical(namespace: str, key: str, nonce: int, value: str) -> str:
    """``<ns>|<key>|<nonce>|<swept value>`` — what a signed note write covers.

    Signed note writes exist for the ``room-owners`` and ``room-allow`` namespaces and nowhere
    else; every other note is world-writable.
    """
    return f"{namespace}|{key}|{nonce}|{sweep(value)}"


@dataclass(frozen=True)
class Identity:
    """A local signing identity. The private key never leaves this process."""

    private_key: ed25519.Ed25519PrivateKey
    did: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.did)

    @classmethod
    def generate(cls) -> Identity:
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(priv, did_from_public_key(priv.public_key()))

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return cls(priv, did_from_public_key(priv.public_key()))

    def seed(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, canonical: str) -> str:
        return b64url(self.private_key.sign(canonical.encode()))


def verify(did: str, signature: str, canonical: str) -> bool:
    """Re-verify a signature offline against the canonical string.

    Note the service does not currently serve stored signatures, so this can only check records
    whose signature you kept yourself.
    """
    try:
        public_key_from_did(did).verify(b64url_decode(signature), canonical.encode())
        return True
    except Exception:  # noqa: BLE001 - any malformed input means 'not verified'
        return False
