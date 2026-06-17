"""
HomeLink Device Manager
========================
Runtime access to this device's identity (load keys, sign, verify peers).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import nacl.signing

from homelink.config.manager import ConfigManager, HomeLinkConfig
from homelink.crypto.keys import DeviceIdentity, KeyPair, DHKeyPair
from homelink.crypto.session import decrypt_private_key

log = logging.getLogger(__name__)


class DeviceManager:
    """
    Loads and holds this device's cryptographic identity at runtime.

    Usage
    -----
        dm = DeviceManager(config_mgr)
        dm.load(password="hunter2")
        signed = dm.identity.signing.sign(b"hello")
    """

    def __init__(self, config_mgr: ConfigManager):
        self._mgr = config_mgr
        self.identity: Optional[DeviceIdentity] = None
        self.config: Optional[HomeLinkConfig] = None
        self._peers: dict[str, DeviceIdentity] = {}

    # ------------------------------------------------------------------ #
    # Load                                                                  #
    # ------------------------------------------------------------------ #

    def load(self, password: str) -> DeviceIdentity:
        """Load identity from disk, decrypt private keys with password."""
        self.config = self._mgr.load_config()

        # Decrypt signing key
        enc_signing = self._mgr.load_encrypted_key("signing")
        signing_priv = decrypt_private_key(enc_signing, password)

        # Decrypt DH key
        enc_dh = self._mgr.load_encrypted_key("dh")
        dh_priv = decrypt_private_key(enc_dh, password)

        import nacl.public
        signing_key = nacl.signing.SigningKey(signing_priv)
        signing_pair = KeyPair(
            signing_key=signing_key,
            verify_key=signing_key.verify_key,
        )

        dh_privkey = nacl.public.PrivateKey(dh_priv)
        dh_pair = DHKeyPair(
            private_key=dh_privkey,
            public_key=dh_privkey.public_key,
        )

        self.identity = DeviceIdentity(
            device_id=self.config.device_id,
            name=self.config.device_name,
            signing=signing_pair,
            dh=dh_pair,
            approved=True,
        )

        # Load known peers
        self._load_peers()
        log.info("Device identity loaded: %s", self.identity.device_id)
        return self.identity

    # ------------------------------------------------------------------ #
    # Peers                                                                 #
    # ------------------------------------------------------------------ #

    def _load_peers(self) -> None:
        raw = self._mgr.load_devices()
        for did, info in raw.items():
            if did == self.identity.device_id:
                continue
            try:
                peer = DeviceIdentity.from_public_dict(info)
                self._peers[did] = peer
            except Exception as e:
                log.warning("Could not load peer %s: %s", did, e)

    def get_peer(self, device_id: str) -> Optional[DeviceIdentity]:
        return self._peers.get(device_id)

    def all_peers(self) -> list[DeviceIdentity]:
        return list(self._peers.values())

    def add_peer(self, peer_info: dict) -> DeviceIdentity:
        peer = DeviceIdentity.from_public_dict(peer_info)
        self._peers[peer.device_id] = peer
        self._mgr.add_device(peer_info)
        log.info("Peer added: %s (%s)", peer.device_id, peer.name)
        return peer

    def approve_peer(self, device_id: str) -> bool:
        ok = self._mgr.approve_device(device_id)
        if ok and device_id in self._peers:
            self._peers[device_id].approved = True
        return ok

    def is_peer_approved(self, device_id: str) -> bool:
        peer = self._peers.get(device_id)
        if peer is None:
            return False
        return peer.approved
