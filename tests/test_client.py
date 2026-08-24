"""End-to-end tests against a real technocore-chat instance, booted locally.

Localhost only, always. The signed lane is the part that cannot be tested against a mock without
testing the mock instead of the protocol, so these run against the actual server or they skip.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

import pytest

from technocore import Client, Identity, TechnocoreError
from technocore.nonce import NonceStore

UPSTREAM = os.path.expanduser("~/Projects/technocore-conformance/upstream")
pytestmark = pytest.mark.skipif(
    not os.path.exists(os.path.join(UPSTREAM, "src", "app.py")) or shutil.which("uv") is None,
    reason="upstream checkout or uv not available",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def server():
    port = _free_port()
    root = tempfile.mkdtemp()
    env = {
        **os.environ,
        "UV_CACHE_DIR": os.path.join(UPSTREAM, ".uvcache"),
        "CHAT_ROOT": root,
        "CHAT_RATE_READ": "1000000",
        "CHAT_RATE_WRITE": "1000000",
        "CHAT_RATE_ROOMS_PER_DAY": "1000000",
    }
    proc = subprocess.Popen(
        ["uv", "run", "uvicorn", "--app-dir", "src", "app:app", "--port", str(port),
         "--log-level", "warning"],
        cwd=UPSTREAM, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1).read()
            break
        except Exception:  # noqa: BLE001 - server not up yet, in any of several ways
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.skip("local server did not come up")

    yield base
    proc.terminate()
    proc.wait(timeout=10)
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def client(server, tmp_path):
    assert "127.0.0.1" in server  # the invariant, asserted rather than assumed
    return Client(
        base_url=server,
        identity=Identity.generate(),
        nick="pytest",
        nonces=NonceStore(tmp_path / "nonces.json"),
        receipts_path=tmp_path / "receipts.jsonl",
    )


def _room(name: str) -> str:
    return f"t{os.urandom(3).hex()}-{name}"


def test_signed_write_is_accepted_and_readable(client):
    room = _room("signed")
    client.say(room, "hello from technocore-py")
    messages = client.read(room)
    assert [m.text for m in messages] == ["hello from technocore-py"]
    assert messages[0].signed


def test_signature_covers_the_swept_text(client):
    """The whole reason this library exists: signing raw input would 403 here."""
    room = _room("sweep")
    client.say(room, "a\u200bb")  # zero-width space
    assert [m.text for m in client.read(room)] == ["a b"]


def test_unsigned_write_is_marked_self_asserted(client):
    room = _room("anon")
    client.say(room, "unsigned line", signed=False)
    message = client.read(room)[0]
    assert not message.signed
    assert message.text == "unsigned line"


def test_nonce_replay_is_refused(client):
    """A second write reusing a spent nonce must be refused by the server."""
    room = _room("nonce")
    client.say(room, "first")
    spent = client.nonces._counters[room]

    import urllib.parse

    from technocore.didkey import message_canonical

    canonical = message_canonical(room, spent, "replay")
    sig = client.identity.sign(canonical)
    quote = urllib.parse.quote
    with pytest.raises(TechnocoreError) as caught:
        client._request(
            f"/r/{quote(room, safe='')}/say-signed/{quote(client.identity.did, safe='')}"
            f"/{sig}/{spent}/{quote('replay', safe='')}"
        )
    assert caught.value.status >= 400


def test_receipts_are_written_for_signed_writes(client):
    import json

    room = _room("receipt")
    client.say(room, "keep the proof")
    lines = [json.loads(line) for line in client.receipts_path.read_text().splitlines()]
    assert len(lines) == 1
    receipt = lines[0]
    assert receipt["scope"] == room
    assert receipt["seq"] == 1
    assert receipt["canonical"].endswith("|keep the proof")

    # The receipt must be independently verifiable offline — the server never returns the sig.
    from technocore import verify

    assert verify(receipt["did"], receipt["sig"], receipt["canonical"])


def test_mailbox_rejects_unsigned(client):
    room = f"mb-p-{os.urandom(6).hex()}"
    with pytest.raises(TechnocoreError) as caught:
        client.say(room, "unsigned into a mailbox", signed=False)
    assert caught.value.status == 403


def test_mailbox_accepts_signed(client):
    room = f"mb-p-{os.urandom(6).hex()}"
    client.say(room, "signed into a mailbox")
    assert [m.text for m in client.read(room)] == ["signed into a mailbox"]


def test_notes_roundtrip_and_conditional_write(client):
    namespace, key = _room("ns"), "state"
    client.set_note(namespace, key, "one")
    assert "one" in client.note(namespace, key)

    client.set_note(namespace, key, "two", if_match="one")
    assert "two" in client.note(namespace, key)

    with pytest.raises(TechnocoreError) as caught:
        client.set_note(namespace, key, "three", if_match="one")  # stale
    assert caught.value.status == 409
    assert "two" in caught.value.body  # the 409 carries what is actually there


def test_if_absent_refuses_an_existing_note(client):
    namespace, key = _room("ns2"), "claim"
    client.set_note(namespace, key, "mine", if_absent=True)
    with pytest.raises(TechnocoreError) as caught:
        client.set_note(namespace, key, "yours", if_absent=True)
    assert caught.value.status == 409


def test_publish_did_note(client):
    client.publish_did(mailbox="mb-p-example", note="repo: example")
    stored = client.note("did", client.identity.fingerprint)
    assert client.identity.did in stored
    assert "mb-p-example" in stored


def test_read_since_returns_only_newer(client):
    room = _room("since")
    client.say(room, "one")
    client.say(room, "two")
    first = client.read(room)[0]
    assert [m.text for m in client.read(room, since=first.seq)] == ["two"]


def test_wait_without_since_is_a_client_error(client):
    with pytest.raises(ValueError, match="wait requires since"):
        client.read("lobby", wait=5)


def test_all_invisible_write_is_refused_before_the_request(client):
    with pytest.raises(ValueError, match="nothing visible"):
        client.say(_room("void"), "\u200b\u200b")


def test_events_lane_is_not_writable(client):
    with pytest.raises(TechnocoreError) as caught:
        client.say("events", "should not land", signed=False)
    assert caught.value.status == 403
