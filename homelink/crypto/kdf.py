"""
HomeLink Key Derivation
=======================
Argon2id for password hashing/KDF.
HKDF-SHA256 (cryptography.hazmat) for session key derivation.

Fixes applied
-------------
- SA-14 : Replaced manual HMAC HKDF with cryptography.hazmat HKDF (RFC 5869 compliant)
- CRYPTO : Random salt per session for HKDF (not fixed constant)
- AUTH   : Password strength validation added
"""

from __future__ import annotations

import os
import re

from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Argon2id parameters — OWASP/RFC 9106 compliant
# ---------------------------------------------------------------------------
_PH = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# Minimum password requirements
_MIN_PASSWORD_LENGTH = 12
_COMMON_PASSWORDS = frozenset({
    "password", "password1", "homelink", "123456789012",
    "qwertyuiop", "letmein123", "admin123456",
})


def validate_password_strength(password: str) -> list[str]:
    """
    Return list of unmet requirements (empty = password acceptable).
    """
    issues = []
    if len(password) < _MIN_PASSWORD_LENGTH:
        issues.append(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        issues.append("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        issues.append("Password must contain at least one digit")
    if password.lower() in _COMMON_PASSWORDS:
        issues.append("Password is too common")
    return issues


def hash_password(password: str) -> str:
    """Hash password for storage. Returns Argon2id encoded string."""
    return _PH.hash(password)


def verify_password(password: str, encoded_hash: str) -> bool:
    """Verify password against stored Argon2id hash. Constant-time comparison."""
    try:
        return _PH.verify(encoded_hash, password)
    except Exception:
        return False


def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive 32-byte ChaCha20 key from password using Argon2id.
    Returns (key, salt). Salt is generated if not provided.
    """
    if salt is None:
        salt = os.urandom(16)
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )
    return key, salt


def derive_session_keys(
    shared_secret: bytes,
    salt: bytes | None = None,
    info: bytes = b"homelink-v1-session",
) -> tuple[bytes, bytes, bytes]:
    """
    Derive two independent 32-byte session keys from DH shared secret.
    Uses HKDF-SHA256 (RFC 5869) with random salt per session.

    Fixes SA-14: uses cryptography.hazmat HKDF (not manual HMAC).
    Fixes CRYPTO: random salt (not constant context string).

    Returns (client_to_server_key, server_to_client_key, salt).
    The salt must be transmitted to the peer so they can reproduce keys.
    """
    if salt is None:
        salt = os.urandom(32)

    # HKDF-SHA256 → 64 bytes → split into two 32-byte keys
    hkdf = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=salt,
        info=info,
    )
    material = hkdf.derive(shared_secret)
    return material[:32], material[32:], salt
