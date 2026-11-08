from __future__ import annotations

import pytest

from threatlens.auth import throttle as throttle_mod
from threatlens.auth.passwords import (
    generate_password,
    hash_password,
    needs_rehash,
    verify_password,
)
from threatlens.auth.throttle import LoginThrottle


def test_hash_is_argon2id_and_verifies() -> None:
    h = hash_password("hunter2-hunter2")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "hunter2-hunter2")
    assert not verify_password(h, "hunter2-hunter3")
    assert not needs_rehash(h)


def test_hashes_are_salted() -> None:
    assert hash_password("same-password-1") != hash_password("same-password-1")


def test_missing_user_never_verifies() -> None:
    assert verify_password(None, "anything-at-all") is False


def test_garbage_hash_is_rejected() -> None:
    assert verify_password("not-a-hash", "whatever-password") is False


@pytest.mark.parametrize("pw", ["short", "x" * 1025])
def test_length_limits(pw: str) -> None:
    with pytest.raises(ValueError, match="characters"):
        hash_password(pw)


def test_overlong_password_not_verified() -> None:
    assert verify_password(hash_password("valid-password!"), "x" * 5000) is False


def test_generated_password_is_strong() -> None:
    a, b = generate_password(), generate_password()
    assert a != b
    assert len(a) >= 24


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    c = FakeClock()
    monkeypatch.setattr(throttle_mod.time, "monotonic", c)
    return c


def test_throttle_blocks_after_max_failures(clock: FakeClock) -> None:
    t = LoginThrottle(max_failures=3, window_seconds=60)
    for _ in range(3):
        assert t.retry_after("1.1.1.1", "admin") == 0
        t.failure("1.1.1.1", "admin")
    assert t.retry_after("1.1.1.1", "admin") > 0
    # Same IP, other username: still blocked by the IP counter.
    assert t.retry_after("1.1.1.1", "bob") > 0
    # Other IP, same username: blocked by the username counter.
    assert t.retry_after("2.2.2.2", "ADMIN") > 0
    # Unrelated IP + user: fine.
    assert t.retry_after("3.3.3.3", "carol") == 0


def test_throttle_window_expires(clock: FakeClock) -> None:
    t = LoginThrottle(max_failures=2, window_seconds=60)
    t.failure("1.1.1.1", "a")
    t.failure("1.1.1.1", "a")
    assert 0 < t.retry_after("1.1.1.1", "a") <= 61
    clock.t += 61
    assert t.retry_after("1.1.1.1", "a") == 0


def test_success_clears_username_but_not_ip(clock: FakeClock) -> None:
    t = LoginThrottle(max_failures=2, window_seconds=60)
    t.failure("1.1.1.1", "victim")
    t.failure("1.1.1.1", "victim")
    t.success("1.1.1.1", "attacker-own-account")
    assert t.retry_after("1.1.1.1", "victim") > 0
    t.success("1.1.1.1", "victim")
    # username counter cleared, IP counter still full
    assert t.retry_after("9.9.9.9", "victim") == 0
    assert t.retry_after("1.1.1.1", "someone") > 0
