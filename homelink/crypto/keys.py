"""
HomeLink Key Management
=======================
Ed25519 signing keys + X25519 key-exchange keys for every device.

Fixes applied
-------------
- SA-13  : Optional private keys for peer identities (no dangling placeholders)
- CRYPTO : X25519 via cryptography.hazmat (pure X25519, no HSalsa20 intermediate)
- CRYPTO : Fingerprint is SHA256(pubkey)[:16] not raw pubkey bytes
- CRYPTO : sign() raises RuntimeError if called on peer-only identity
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional

import nacl.signing
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


@dataclass
class KeyPair:
    """Ed25519 signing key pair. signing_key is None for peer-only identities."""

    verify_key:  nacl.signing.VerifyKey
    signing_key: Optional[nacl.signing.SigningKey] = None

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = nacl.signing.SigningKey.generate()
        return cls(verify_key=sk.verify_key, signing_key=sk)

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        sk = nacl.signing.SigningKey(seed)
        return cls(verify_key=sk.verify_key, signing_key=sk)

    @classmethod
    def from_public_bytes(cls, pub: bytes) -> "KeyPair":
        """Peer-only key pair. Cannot sign."""
        return cls(verify_key=nacl.signing.VerifyKey(pub))

    def sign(self, message: bytes) -> bytes:
        """Return 64-byte Ed25519 signature. Raises if no private key."""
        if self.signing_key is None:
            raise RuntimeError(
                "Cannot sign: this is a peer-only identity (no private key loaded). "
                "Attempting to sign with a peer identity is a programming error."
            )
        return bytes(self.signing_key.sign(message).signature)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Return True if signature valid."""
        try:
            self.verify_key.verify(message, signature)
            return True
        except Exception:
            return False

    def has_private_key(self) -> bool:
        return self.signing_key is not None

    @property
    def public_bytes(self) -> bytes:
        return bytes(self.verify_key)

    @property
    def private_bytes(self) -> bytes:
        if self.signing_key is None:
            raise RuntimeError("No private key (peer-only identity)")
        return bytes(self.signing_key)

    def to_dict(self) -> dict:
        d: dict = {"public": self.public_bytes.hex()}
        if self.signing_key is not None:
            d["private"] = self.private_bytes.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "KeyPair":
        if "private" in d:
            sk = nacl.signing.SigningKey(bytes.fromhex(d["private"]))
            return cls(verify_key=sk.verify_key, signing_key=sk)
        return cls.from_public_bytes(bytes.fromhex(d["public"]))


@dataclass
class DHKeyPair:
    """
    X25519 key pair using cryptography.hazmat (pure X25519, no NaCl intermediary).
    private_key is None for peer-only identities.

    Fixes SA-13 (no dangling placeholder keys).
    Fixes CRYPTO (pure X25519 via hazmat, not HSalsa20-wrapped NaCl Box).
    """

    public_key:  X25519PublicKey
    private_key: Optional[X25519PrivateKey] = None

    @classmethod
    def generate(cls) -> "DHKeyPair":
        priv = X25519PrivateKey.generate()
        return cls(public_key=priv.public_key(), private_key=priv)

    @classmethod
    def from_public_bytes(cls, pub_bytes: bytes) -> "DHKeyPair":
        """Peer-only — cannot perform DH exchange."""
        return cls(public_key=X25519PublicKey.from_public_bytes(pub_bytes))

    def exchange(self, their_public_bytes: bytes) -> bytes:
        """X25519 DH → 32-byte shared secret. Raises if no private key."""
        if self.private_key is None:
            raise RuntimeError("Cannot exchange: peer-only identity (no DH private key)")
        their_pub = X25519PublicKey.from_public_bytes(their_public_bytes)
        return self.private_key.exchange(their_pub)

    def has_private_key(self) -> bool:
        return self.private_key is not None

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()

    @property
    def private_bytes(self) -> bytes:
        if self.private_key is None:
            raise RuntimeError("No DH private key (peer-only identity)")
        return self.private_key.private_bytes_raw()

    def to_dict(self) -> dict:
        d: dict = {"public": self.public_bytes.hex()}
        if self.private_key is not None:
            d["private"] = self.private_bytes.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DHKeyPair":
        if "private" in d:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(d["private"]))
            return cls(public_key=priv.public_key(), private_key=priv)
        return cls.from_public_bytes(bytes.fromhex(d["public"]))


@dataclass
class DeviceIdentity:
    """
    Complete cryptographic identity for a HomeLink device.

    For own device: signing.has_private_key() and dh.has_private_key() are True.
    For peer devices: only public keys are present (no private keys).
    """

    device_id: str
    name:      str
    signing:   KeyPair
    dh:        DHKeyPair
    approved:  bool = False
    role:      str  = "viewer"     # RBAC: viewer | operator | administrator
    metadata:  dict = field(default_factory=dict)

    @classmethod
    def generate(cls, name: str) -> "DeviceIdentity":
        """Generate a fresh device identity with both keypairs."""
        signing = KeyPair.generate()
        dh      = DHKeyPair.generate()
        return cls(
            device_id=_derive_device_id(signing.public_bytes),
            name=name,
            signing=signing,
            dh=dh,
            approved=False,
            role="viewer",
        )

    @property
    def fingerprint(self) -> str:
        """
        SHA-256-based fingerprint (colon-separated hex pairs of first 16 bytes).
        Using SHA256(pubkey) rather than raw pubkey bytes is more robust.
        """
        digest = hashlib.sha256(self.signing.public_bytes).digest()[:16]
        return ":".join(f"{b:02x}" for b in digest)

    def public_info(self) -> dict:
        """Shareable public identity — never contains private keys."""
        return {
            "device_id":      self.device_id,
            "name":           self.name,
            "signing_public": self.signing.public_bytes.hex(),
            "dh_public":      self.dh.public_bytes.hex(),
            "approved":       self.approved,
            "role":           self.role,
            "fingerprint":    self.fingerprint,
            "metadata":       self.metadata,
        }

    def to_dict(self) -> dict:
        """
        Full serialization including private keys.
        MUST be encrypted before writing to disk.
        """
        d = {
            "device_id": self.device_id,
            "name":      self.name,
            "signing":   self.signing.to_dict(),
            "dh":        self.dh.to_dict(),
            "approved":  self.approved,
            "role":      self.role,
            "metadata":  self.metadata,
        }
        # Verify we're not accidentally serializing without private keys
        assert "private" in d["signing"], "to_dict called on peer-only identity"
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceIdentity":
        return cls(
            device_id=d["device_id"],
            name=d["name"],
            signing=KeyPair.from_dict(d["signing"]),
            dh=DHKeyPair.from_dict(d["dh"]),
            approved=d.get("approved", False),
            role=d.get("role", "viewer"),
            metadata=d.get("metadata", {}),
        )

    @classmethod
    def from_public_dict(cls, d: dict) -> "DeviceIdentity":
        """
        Reconstruct peer identity from public info.
        No private keys are created or stored. (Fixes SA-13.)
        """
        return cls(
            device_id=d["device_id"],
            name=d["name"],
            signing=KeyPair.from_public_bytes(bytes.fromhex(d["signing_public"])),
            dh=DHKeyPair.from_public_bytes(bytes.fromhex(d["dh_public"])),
            approved=d.get("approved", False),
            role=d.get("role", "viewer"),
            metadata=d.get("metadata", {}),
        )


def _derive_device_id(public_key_bytes: bytes) -> str:
    """Device ID = first 16 uppercase hex chars of SHA-256(public_key)."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16].upper()
