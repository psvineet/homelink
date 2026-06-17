"""
HomeLink Message Signing
========================
All messages signed with Ed25519. All responses signed by responder.

Fixes applied
-------------
- SA-04 / SA-17 : global nonce cache replaced with per-session NonceCache instances
- CRYPTO-01      : device_id and version now included in signed bytes (prevents device spoofing)
- CRYPTO-02      : version downgrade protection included in signed bytes

Envelope format (JSON-serializable)
------------------------------------
{
    "payload":    "<base64-encoded payload bytes>",
    "signature":  "<base64-encoded 64-byte Ed25519 sig>",
    "device_id":  "<sender device ID>",
    "timestamp":  <unix timestamp float>,
    "nonce":      "<16-byte hex random nonce>",
    "version":    1
}

Security decisions
------------------
- Timestamp validated ±30s; rejects stale replayed envelopes.
- Per-session NonceCache prevents replay within TTL window (120s).
- device_id + version are inside the signed blob (prevents substitution attacks).
"""

from __future__ import annotations

import base64
import hashlib
import os
import time

import nacl.signing

from homelink.crypto.nonce_cache import NonceCache

TIMESTAMP_TOLERANCE = 30.0   # seconds — max clock skew accepted
ENVELOPE_VERSION    = 1


def sign_message(
    payload: bytes,
    signing_key: nacl.signing.SigningKey,
    device_id: str,
) -> dict:
    """
    Wrap payload in signed envelope.
    device_id and version are inside the signed bytes — not forgeable.
    """
    timestamp = time.time()
    nonce = os.urandom(16).hex()

    to_sign = _canonical_bytes(payload, timestamp, nonce, device_id, ENVELOPE_VERSION)
    sig = bytes(signing_key.sign(to_sign).signature)

    return {
        "payload":   base64.b64encode(payload).decode(),
        "signature": base64.b64encode(sig).decode(),
        "device_id": device_id,
        "timestamp": timestamp,
        "nonce":     nonce,
        "version":   ENVELOPE_VERSION,
    }


def verify_signature(
    envelope: dict,
    verify_key: nacl.signing.VerifyKey,
    nonce_cache: NonceCache,
) -> bytes:
    """
    Verify envelope. Returns raw payload bytes on success.

    Parameters
    ----------
    envelope    : signed envelope dict
    verify_key  : sender's Ed25519 verify key (from approved devices list)
    nonce_cache : per-session NonceCache — prevents replay

    Raises
    ------
    ValueError  : bad signature, bad timestamp, replay, or version mismatch
    """
    _check_version(envelope)
    _check_timestamp(envelope["timestamp"])
    nonce_cache.check_and_add(envelope["nonce"])   # per-session, not global

    device_id = envelope.get("device_id", "")
    payload   = base64.b64decode(envelope["payload"])
    sig       = base64.b64decode(envelope["signature"])
    version   = envelope["version"]

    to_sign = _canonical_bytes(payload, envelope["timestamp"], envelope["nonce"], device_id, version)

    try:
        verify_key.verify(to_sign, sig)
    except Exception as e:
        raise ValueError(f"Signature verification failed: {e}") from e

    return payload


def _canonical_bytes(
    payload: bytes,
    timestamp: float,
    nonce: str,
    device_id: str,
    version: int,
) -> bytes:
    """
    Deterministic bytes-to-sign.

    SHA256(payload) || timestamp_ms(8) || nonce(utf8) || device_id(utf8) || version(2)

    Including device_id and version prevents:
    - Cross-device signature reuse (SA-01 variant)
    - Version downgrade attacks
    """
    payload_hash = hashlib.sha256(payload).digest()
    ts_bytes     = int(timestamp * 1000).to_bytes(8, "big")
    ver_bytes    = version.to_bytes(2, "big")
    return (
        payload_hash
        + ts_bytes
        + nonce.encode("utf-8")
        + device_id.encode("utf-8")
        + ver_bytes
    )


def _check_version(envelope: dict) -> None:
    v = envelope.get("version", 0)
    if v != ENVELOPE_VERSION:
        raise ValueError(f"Unknown envelope version: {v!r}")


def _check_timestamp(ts: float) -> None:
    delta = abs(time.time() - ts)
    if delta > TIMESTAMP_TOLERANCE:
        raise ValueError(
            f"Timestamp out of range: {delta:.1f}s drift (max {TIMESTAMP_TOLERANCE}s)"
        )
