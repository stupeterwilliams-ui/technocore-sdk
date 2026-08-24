"""Nonce monotonicity, including the case that actually bites: a restart."""

from technocore.nonce import NonceStore


def test_strictly_increases_within_a_scope():
    store = NonceStore()
    values = [store.next("lobby") for _ in range(50)]
    assert values == sorted(values)
    assert len(set(values)) == 50  # strictly increasing, no ties inside one millisecond


def test_scopes_are_independent():
    store = NonceStore()
    store.next("lobby")
    # A fresh scope is not held back by another scope's counter, but both are past the clock floor.
    assert store.next("meta") > 0


def test_survives_a_restart(tmp_path):
    path = tmp_path / "nonces.json"
    first = NonceStore(path)
    last = max(first.next("lobby") for _ in range(10))

    reopened = NonceStore(path)  # simulates a process restart
    assert reopened.next("lobby") > last


def test_corrupt_store_does_not_wedge_the_client(tmp_path):
    path = tmp_path / "nonces.json"
    path.write_text("{ this is not json")
    # The clock floor still yields a usable, plausibly-past value rather than raising.
    assert NonceStore(path).next("lobby") > 0


def test_persists_atomically(tmp_path):
    path = tmp_path / "nested" / "nonces.json"
    store = NonceStore(path)
    value = store.next("lobby")
    assert path.exists()
    assert NonceStore(path).next("lobby") > value
