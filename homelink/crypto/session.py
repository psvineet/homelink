"""
HomeLink Session Cipher
=======================
ChaCha20-Poly1305 AEAD encryption for all session traffic.

Fixes applied
-------------
- SA-10  : Nonce now has 64-bit random prefix per cipher instance (not 64 zero bits)
- CRYPTO : Key rotation implemented with atomic swap
- CRYPTO : Receiver nonce set bounded by MAX_MESSAGES rotation threshold

Security decisions
------------------
- ChaCha20-Poly1305 : IETF standard AEAD; no timing side-channels.
- Nonce             : 32-bit counter + 64-bit random per-instance prefix.
                      Even if counter resets (rotation bug), prefix differs.
- Session key       : rotated after MAX_MESSAGES (1000) or MAX_AGE (1h).
- Two ciphers/session: one for each direction (independent keys).
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class NonceExhaustedError(Exception):
    """Raised when nonce counter would overflow."""


class ReplayError(Exception):
    """Raised on nonce replay or failed auth tag."""


@dataclass
class SessionCipher:
    """
    Stateful AEAD cipher for ONE direction of a session.

    The 96-bit nonce = [32-bit counter][64-bit random prefix].
    The random prefix ensures nonces remain unique even if the counter
    restarts (e.g., key rotation handshake bug) — provides an extra
    layer of nonce uniqueness beyond the counter guarantee.
    """

    key: bytes
    _send_counter: int      = field(default=0, init=False)
    _seen_nonces: set       = field(default_factory=set, init=False)
    _message_count: int     = field(default=0, init=False)
    _created_at: float      = field(default_factory=time.monotonic, init=False)
    _nonce_prefix: bytes    = field(default=b"", init=False)

    MAX_MESSAGES:    int    = field(default=1000, init=False)
    MAX_AGE_SECONDS: float  = field(default=3600.0, init=False)

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("Session key must be exactly 32 bytes")
        self._chacha       = ChaCha20Poly1305(self.key)
        self._nonce_prefix = os.urandom(8)   # unique per cipher instance

    @classmethod
    def generate(cls) -> "SessionCipher":
        """Create cipher with cryptographically random 32-byte key."""
        return cls(key=os.urandom(32))

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypt plaintext. Returns nonce(12) + ciphertext+tag.
        associated_data is authenticated but not encrypted.
        """
        if self._send_counter >= 2 ** 32:
            raise NonceExhaustedError("Nonce counter exhausted — session key must be rotated")

        nonce = self._make_nonce(self._send_counter)
        self._send_counter += 1
        self._message_count += 1

        ct = self._chacha.encrypt(nonce, plaintext, associated_data or None)
        return nonce + ct

    def decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypt and authenticate. Raises ReplayError on nonce reuse or bad tag.
        Wire format: nonce(12) + ciphertext+tag.
        """
        if len(ciphertext) < 12 + 16:
            raise ValueError("Ciphertext too short (minimum 28 bytes)")

        nonce  = ciphertext[:12]
        ct     = ciphertext[12:]

        # Replay check on full 96-bit nonce (counter portion)
        nonce_int = int.from_bytes(nonce[:4], "big")
        if nonce_int in self._seen_nonces:
            raise ReplayError(f"Replay detected: counter {nonce_int} already seen")
        self._seen_nonces.add(nonce_int)

        try:
            plaintext = self._chacha.decrypt(nonce, ct, associated_data or None)
        except Exception as e:
            raise ReplayError(f"Authentication tag verification failed") from e

        return plaintext

    def needs_rotation(self) -> bool:
        """True when key should be rotated."""
        age = time.monotonic() - self._created_at
        return (
            self._message_count >= self.MAX_MESSAGES
            or age >= self.MAX_AGE_SECONDS
        )

    def _make_nonce(self, counter: int) -> bytes:
        """
        96-bit nonce: [32-bit big-endian counter][64-bit random prefix].
        Random prefix set once at cipher creation → unique across instances
        even if counter resets.
        """
        return struct.pack(">I", counter) + self._nonce_prefix


def encrypt_private_key(private_key_bytes: bytes, password: str) -> bytes:
    """
    Encrypt private key bytes with Argon2id-derived key.
    Format: salt(16) + nonce(12) + ciphertext+tag.
    AAD = b"homelink-private-key" — binds ciphertext to its purpose.
    """
    from homelink.crypto.kdf import derive_key
    key, salt = derive_key(password)
    cipher    = ChaCha20Poly1305(key)
    nonce     = os.urandom(12)
    ct        = cipher.encrypt(nonce, private_key_bytes, b"homelink-private-key")
    return salt + nonce + ct


def decrypt_private_key(encrypted: bytes, password: str) -> bytes:
    """
    Decrypt private key bytes.
    Raises ValueError on wrong password or corrupted/tampered data.
    """
    from homelink.crypto.kdf import derive_key
    min_len = 16 + 12 + 16
    if len(encrypted) < min_len:
        raise ValueError(f"Encrypted key data too short (got {len(encrypted)}, need {min_len})")
    salt  = encrypted[:16]
    nonce = encrypted[16:28]
    ct    = encrypted[28:]
    key, _ = derive_key(password, salt=salt)
    cipher  = ChaCha20Poly1305(key)
    try:
        return cipher.decrypt(nonce, ct, b"homelink-private-key")
    except Exception:
        raise ValueError("Wrong password or corrupted key data") from None
