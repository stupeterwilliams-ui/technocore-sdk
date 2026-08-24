"""Contribution proofs — binding a ``did:key`` to a public artifact.

A contribution proof is a small signed JSON file committed into a repository, asserting: *the
holder of this key claims this artifact, at this commit.* It is the public half of the receipts
problem — the service discards signatures, so a durable, checkable claim has to live somewhere the
author controls.

    {
      "artifact_url": "https://github.com/owner/repo",
      "commit": "<40-hex>",
      "did": "did:key:z6Mk...",
      "schema": "technocore-contribution-proof-v1",
      "signature": "<86 base64url chars>"
    }

**The canonical string is the whole contract**, and the reason this module exists::

    technocore-contribution-proof-v1|<did>|<artifact_url>|<commit>

Pipe-joined, in that fixed order, UTF-8. It deliberately matches the shape technocore-chat already
uses for its own signed lanes (``<room>|<nonce>|<text>`` and ``<ns>|<key>|<nonce>|<value>``) rather
than inventing a JSON canonicalisation, because "sign the JSON" is ambiguous — key order, spacing,
Unicode escaping and trailing newlines all change the bytes, and every implementation picks
differently. That ambiguity is not hypothetical: the proof in `ritesh59697/technocore-dashboard`,
the artifact that popularised this schema name, could not be verified here under 49 candidate
canonicalisations. The schema shape is a good idea; without a published canonical string it is not
checkable by anyone but its author, which defeats the point.

So: this canonicalisation is published, implemented both ways here, and covered by tests. Anyone
can re-derive it.

**What a proof does and does not establish.** It proves the key-holder made the claim. It does not
prove they wrote the code, that the URL is theirs, or that the artifact is any good. It attests one
specific commit — not the repository forever — so a proof naming an older commit says nothing
about later ones.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .didkey import Identity, verify

SCHEMA = "technocore-contribution-proof-v1"
FILENAME = "contribution-proof.json"

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def canonical(did: str, artifact_url: str, commit: str) -> str:
    """The exact bytes a contribution proof signs.

    >>> canonical("did:key:zABC", "https://example.com/r", "a" * 40)
    'technocore-contribution-proof-v1|did:key:zABC|https://example.com/r|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    """
    for name, value in (("did", did), ("artifact_url", artifact_url), ("commit", commit)):
        if "|" in value:
            raise ValueError(f"{name} contains '|', which would make the canonical string ambiguous")
        if not value:
            raise ValueError(f"{name} is empty")
    return f"{SCHEMA}|{did}|{artifact_url}|{commit}"


@dataclass(frozen=True)
class Proof:
    artifact_url: str
    commit: str
    did: str
    signature: str
    schema: str = SCHEMA

    def as_dict(self) -> dict[str, Any]:
        # Sorted keys, so the committed file is byte-stable across regenerations.
        return {
            "artifact_url": self.artifact_url,
            "commit": self.commit,
            "did": self.did,
            "schema": self.schema,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n"

    @property
    def canonical_string(self) -> str:
        return canonical(self.did, self.artifact_url, self.commit)

    def verify(self) -> bool:
        """True if the signature checks out against the published canonical string."""
        if self.schema != SCHEMA:
            return False
        return verify(self.did, self.signature, self.canonical_string)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Proof:
        missing = {"artifact_url", "commit", "did", "schema", "signature"} - set(data)
        if missing:
            raise ValueError(f"proof is missing {', '.join(sorted(missing))}")
        return cls(
            artifact_url=data["artifact_url"],
            commit=data["commit"],
            did=data["did"],
            signature=data["signature"],
            schema=data["schema"],
        )

    @classmethod
    def load(cls, path: str | Path) -> Proof:
        return cls.from_dict(json.loads(Path(path).read_text()))


def create_proof(identity: Identity, artifact_url: str, commit: str) -> Proof:
    """Sign a contribution proof.

    *commit* must be a full 40-character hex sha: an abbreviated hash is ambiguous, and a proof
    that cannot be resolved to exactly one commit is not evidence of anything.
    """
    if not _COMMIT_RE.match(commit):
        raise ValueError(f"commit must be a full 40-character hex sha, got {commit!r}")
    signature = identity.sign(canonical(identity.did, artifact_url, commit))
    return Proof(artifact_url=artifact_url, commit=commit, did=identity.did, signature=signature)


def _main(argv: list[str] | None = None) -> int:
    """`python -m technocore_sdk.proof verify <path>` — so anyone can check ours."""
    import argparse

    parser = argparse.ArgumentParser(prog="technocore_sdk.proof", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="verify a contribution proof file")
    v.add_argument("path", nargs="?", default=FILENAME)

    c = sub.add_parser("canonical", help="print the canonical string a proof file signs")
    c.add_argument("path", nargs="?", default=FILENAME)

    args = parser.parse_args(argv)
    try:
        proof = Proof.load(args.path)
    except (OSError, ValueError) as exc:
        print(f"could not read a proof from {args.path}: {exc}")
        return 2

    if args.command == "canonical":
        print(proof.canonical_string)
        return 0

    if proof.verify():
        print(f"VALID   {proof.did}\n        claims {proof.artifact_url}\n        at commit {proof.commit}")
        return 0
    print(f"INVALID {args.path} — signature does not verify against:\n        {proof.canonical_string}")
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())


# Short alias for in-module use and backwards-friendly imports.
create = create_proof
