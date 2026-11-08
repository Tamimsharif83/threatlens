"""Password hashing with argon2id (argon2-cffi's RFC 9106 low-memory profile)."""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.profiles import RFC_9106_LOW_MEMORY

_hasher = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)

# Verified against when a username does not exist, so a failed login takes the
# same time whether or not the account exists (no username enumeration by timing).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024  # argon2 accepts more, but there's no reason to hash megabytes


def hash_password(password: str) -> str:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters long"
        )
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-effort verification. ``password_hash=None`` means "no such user"."""
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def generate_password() -> str:
    """A random password suitable for printing once (~144 bits)."""
    return secrets.token_urlsafe(18)
