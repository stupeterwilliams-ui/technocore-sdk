"""Contribution proofs.

The canonicalisation is the whole contract, so it is pinned to an exact string here. If someone
changes the join order or the separator, these fail — which is the point: every proof already
signed would silently stop verifying.
"""

import json

import pytest

from technocore_sdk.didkey import Identity
from technocore_sdk.proof import SCHEMA, Proof, canonical, create

SEED = bytes([7]) * 32
URL = "https://github.com/stupeterwilliams-ui/technocore-sdk"
COMMIT = "a" * 40


def test_canonical_string_is_exact():
    did = Identity.from_seed(SEED).did
    assert canonical(did, URL, COMMIT) == f"{SCHEMA}|{did}|{URL}|{COMMIT}"


def test_canonical_rejects_pipe_in_any_field():
    # A pipe in a field would let two different proofs produce the same canonical string.
    with pytest.raises(ValueError, match="ambiguous"):
        canonical("did:key:z|evil", URL, COMMIT)
    with pytest.raises(ValueError, match="ambiguous"):
        canonical("did:key:zABC", "https://e.com/a|b", COMMIT)


def test_canonical_rejects_empty_fields():
    with pytest.raises(ValueError, match="empty"):
        canonical("", URL, COMMIT)


def test_roundtrip_verifies():
    proof = create(Identity.from_seed(SEED), URL, COMMIT)
    assert proof.verify()
    assert proof.schema == SCHEMA


def test_signature_is_deterministic():
    # Ed25519 is deterministic, so regenerating a proof must not churn the committed file.
    a = create(Identity.from_seed(SEED), URL, COMMIT)
    b = create(Identity.from_seed(SEED), URL, COMMIT)
    assert a.to_json() == b.to_json()


def test_tampering_is_caught():
    proof = create(Identity.from_seed(SEED), URL, COMMIT)
    for field, value in [
        ("artifact_url", "https://github.com/someone-else/repo"),
        ("commit", "b" * 40),
        ("did", Identity.generate().did),
        ("schema", "technocore-contribution-proof-v2"),
    ]:
        tampered = Proof.from_dict({**proof.as_dict(), field: value})
        assert not tampered.verify(), f"tampering with {field} was not caught"


def test_commit_must_be_a_full_sha():
    identity = Identity.from_seed(SEED)
    for bad in ("a" * 7, "a" * 39, "A" * 40, "g" * 40, ""):
        with pytest.raises(ValueError, match="40-character hex"):
            create(identity, URL, bad)


def test_file_roundtrip(tmp_path):
    proof = create(Identity.from_seed(SEED), URL, COMMIT)
    path = tmp_path / "contribution-proof.json"
    path.write_text(proof.to_json())
    assert Proof.load(path).verify()
    # Field set matches the schema exactly — no extra fields, none missing.
    assert set(json.loads(path.read_text())) == {
        "artifact_url", "commit", "did", "schema", "signature"
    }


def test_load_rejects_incomplete_proof(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"did": "did:key:zABC", "schema": SCHEMA}))
    with pytest.raises(ValueError, match="missing"):
        Proof.load(path)


def test_cli_verify(tmp_path, capsys):
    from technocore_sdk.proof import _main

    good = tmp_path / "good.json"
    good.write_text(create(Identity.from_seed(SEED), URL, COMMIT).to_json())
    assert _main(["verify", str(good)]) == 0
    assert "VALID" in capsys.readouterr().out

    bad = tmp_path / "bad.json"
    proof = create(Identity.from_seed(SEED), URL, COMMIT)
    bad.write_text(json.dumps({**proof.as_dict(), "commit": "b" * 40}))
    assert _main(["verify", str(bad)]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_cli_canonical(tmp_path, capsys):
    from technocore_sdk.proof import _main

    path = tmp_path / "p.json"
    proof = create(Identity.from_seed(SEED), URL, COMMIT)
    path.write_text(proof.to_json())
    assert _main(["canonical", str(path)]) == 0
    assert capsys.readouterr().out.strip() == proof.canonical_string
