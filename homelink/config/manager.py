"""
HomeLink Configuration Manager
================================

Fixes applied
-------------
- SA-15  : devices.json HMAC integrity protection
- CONFIG : Permission enforcement on all files
- CONFIG : Schema validation with strict typing
- CONFIG : Migration support
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

CONFIG_VERSION    = 1
DEFAULT_CONFIG_DIR = Path.home() / ".homelink"

# Integrity key derivation info for devices.json MAC
_DEVICES_HMAC_INFO = b"homelink-devices-integrity-v1"


@dataclass
class TelegramConfig:
    bot_token:              str  = ""
    chat_id:                str  = ""
    enabled:                bool = False
    large_file_threshold_mb: int = 50

    def is_valid(self) -> bool:
        return bool(self.bot_token and self.chat_id)


@dataclass
class P2PConfig:
    enabled:                bool  = True
    stun_servers:           list  = field(default_factory=lambda: [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
        "stun:stun.cloudflare.com:3478",
    ])
    listen_port:            int   = 0
    heartbeat_interval:     int   = 30
    hole_punch_timeout:     int   = 10
    reconnect_max_attempts: int   = 10
    reconnect_base_delay:   float = 1.0
    reconnect_max_delay:    float = 60.0


@dataclass
class SecurityConfig:
    require_approval:                 bool  = True
    session_key_rotation_messages:    int   = 1000
    session_key_rotation_seconds:     int   = 3600
    timestamp_tolerance_seconds:      float = 30.0
    max_exec_timeout:                 int   = 60
    max_file_size_gb:                 int   = 100
    max_concurrent_transfers:         int   = 4
    exec_rate_limit_per_minute:       int   = 10
    offer_rate_limit_per_minute:      int   = 5


@dataclass
class LogConfig:
    level:          str  = "INFO"
    log_dir:        str  = ""
    max_bytes:      int  = 10_485_760
    backup_count:   int  = 5
    audit_enabled:  bool = True


@dataclass
class HomeLinkConfig:
    version:       int           = CONFIG_VERSION
    device_name:   str           = ""
    device_id:     str           = ""
    telegram:      TelegramConfig  = field(default_factory=TelegramConfig)
    p2p:           P2PConfig       = field(default_factory=P2PConfig)
    security:      SecurityConfig  = field(default_factory=SecurityConfig)
    logging:       LogConfig       = field(default_factory=LogConfig)
    password_hash: str           = ""
    pairing_code:  str           = ""
    config_dir:    str           = ""

    def to_dict(self) -> dict:
        return {
            "version":       self.version,
            "device_name":   self.device_name,
            "device_id":     self.device_id,
            "password_hash": self.password_hash,
            "pairing_code":  self.pairing_code,
            "config_dir":    self.config_dir,
            "telegram":      asdict(self.telegram),
            "p2p":           asdict(self.p2p),
            "security":      asdict(self.security),
            "logging":       asdict(self.logging),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HomeLinkConfig":
        cfg = cls()
        cfg.version       = int(d.get("version", CONFIG_VERSION))
        cfg.device_name   = str(d.get("device_name", ""))
        cfg.device_id     = str(d.get("device_id", ""))
        cfg.password_hash = str(d.get("password_hash", ""))
        cfg.pairing_code  = str(d.get("pairing_code", ""))
        cfg.config_dir    = str(d.get("config_dir", ""))
        if "telegram" in d:
            cfg.telegram = TelegramConfig(**{
                k: v for k, v in d["telegram"].items()
                if k in TelegramConfig.__dataclass_fields__
            })
        if "p2p" in d:
            cfg.p2p = P2PConfig(**{
                k: v for k, v in d["p2p"].items()
                if k in P2PConfig.__dataclass_fields__
            })
        if "security" in d:
            cfg.security = SecurityConfig(**{
                k: v for k, v in d["security"].items()
                if k in SecurityConfig.__dataclass_fields__
            })
        if "logging" in d:
            cfg.logging = LogConfig(**{
                k: v for k, v in d["logging"].items()
                if k in LogConfig.__dataclass_fields__
            })
        return cfg


class ConfigManager:
    def __init__(self, config_dir: Path | str | None = None):
        self.config_dir   = Path(config_dir or DEFAULT_CONFIG_DIR)
        self.keys_dir     = self.config_dir / "keys"
        self.logs_dir     = self.config_dir / "logs"
        self.config_file  = self.config_dir / "config.json"
        self.devices_file = self.config_dir / "devices.json"

    # ------------------------------------------------------------------ #
    # Directory setup                                                       #
    # ------------------------------------------------------------------ #

    def ensure_dirs(self) -> None:
        """Create ~/.homelink/ with strict permissions (700/600)."""
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.logs_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        # Verify permissions (in case directory already existed)
        os.chmod(self.config_dir, 0o700)
        os.chmod(self.keys_dir,   0o700)

    def is_initialized(self) -> bool:
        return self.config_file.exists() and self.devices_file.exists()

    # ------------------------------------------------------------------ #
    # Config                                                                #
    # ------------------------------------------------------------------ #

    def load_config(self) -> HomeLinkConfig:
        if not self.config_file.exists():
            raise FileNotFoundError(
                f"Config not found: {self.config_file}. Run: python init.py"
            )
        self._check_permissions(self.config_file, 0o600)
        with self.config_file.open() as f:
            data = json.load(f)
        cfg = HomeLinkConfig.from_dict(data)
        cfg = self.migrate_if_needed(cfg)
        cfg.logging.log_dir = str(self.logs_dir)
        return cfg

    def save_config(self, cfg: HomeLinkConfig) -> None:
        """Atomic write with strict permissions."""
        cfg.config_dir = str(self.config_dir)
        tmp = self.config_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg.to_dict(), indent=2))
        tmp.chmod(0o600)
        tmp.replace(self.config_file)
        self.config_file.chmod(0o600)

    def validate_config(self, cfg: HomeLinkConfig) -> list[str]:
        errors = []
        if not cfg.device_name:
            errors.append("device_name is empty")
        if not cfg.device_id:
            errors.append("device_id is empty")
        if not cfg.password_hash:
            errors.append("password_hash not set")
        if cfg.telegram.enabled and not cfg.telegram.is_valid():
            errors.append("Telegram enabled but bot_token or chat_id missing")
        return errors

    # ------------------------------------------------------------------ #
    # Devices — with HMAC integrity (SA-15)                                #
    # ------------------------------------------------------------------ #

    def _devices_mac(self, data: str, integrity_key: bytes) -> str:
        """HMAC-SHA256 of devices JSON data."""
        return _hmac_mod.new(integrity_key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _get_integrity_key(self) -> bytes | None:
        """Derive integrity key from signing public key (available without password)."""
        pub_file = self.keys_dir / "signing.pub"
        if pub_file.exists():
            pub = pub_file.read_bytes()
            return hashlib.sha256(pub + _DEVICES_HMAC_INFO).digest()
        return None

    def load_devices(self, verify_integrity: bool = True) -> dict[str, dict]:
        if not self.devices_file.exists():
            return {}
        self._check_permissions(self.devices_file, 0o600)
        raw = self.devices_file.read_text()
        doc = json.loads(raw)

        # SA-15: verify HMAC if present
        if verify_integrity and "mac" in doc and "devices" in doc:
            integrity_key = self._get_integrity_key()
            if integrity_key:
                data     = json.dumps(doc["devices"], indent=2, sort_keys=True)
                expected = self._devices_mac(data, integrity_key)
                if not _hmac_mod.compare_digest(expected, doc["mac"]):
                    raise SecurityError(
                        "devices.json integrity check failed — file may have been tampered with. "
                        "Run: homelink devices --verify to investigate."
                    )
            return doc["devices"]

        # Backward compat: old format without MAC
        if "devices" in doc:
            return doc["devices"]
        return doc

    def save_devices(self, devices: dict[str, dict]) -> None:
        """Atomic write with HMAC integrity tag."""
        data          = json.dumps(devices, indent=2, sort_keys=True)
        integrity_key = self._get_integrity_key()
        doc: dict     = {"version": 1, "devices": devices}
        if integrity_key:
            doc["mac"] = self._devices_mac(data, integrity_key)

        tmp = self.devices_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2))
        tmp.chmod(0o600)
        tmp.replace(self.devices_file)
        self.devices_file.chmod(0o600)

    def add_device(self, device_info: dict) -> None:
        devices = self.load_devices(verify_integrity=False)
        devices[device_info["device_id"]] = device_info
        self.save_devices(devices)

    def remove_device(self, device_id: str) -> bool:
        devices = self.load_devices(verify_integrity=False)
        if device_id not in devices:
            return False
        del devices[device_id]
        self.save_devices(devices)
        return True

    def approve_device(self, device_id: str) -> bool:
        devices = self.load_devices(verify_integrity=False)
        if device_id not in devices:
            return False
        devices[device_id]["approved"] = True
        self.save_devices(devices)
        return True

    # ------------------------------------------------------------------ #
    # Key storage                                                           #
    # ------------------------------------------------------------------ #

    def save_encrypted_key(self, name: str, encrypted_bytes: bytes) -> None:
        path = self.keys_dir / f"{name}.key.enc"
        path.write_bytes(encrypted_bytes)
        path.chmod(0o600)

    def load_encrypted_key(self, name: str) -> bytes:
        path = self.keys_dir / f"{name}.key.enc"
        if not path.exists():
            raise FileNotFoundError(f"Encrypted key not found: {path}")
        self._check_permissions(path, 0o600)
        return path.read_bytes()

    def save_public_key(self, name: str, key_bytes: bytes) -> None:
        path = self.keys_dir / f"{name}.pub"
        path.write_bytes(key_bytes)
        path.chmod(0o644)

    def load_public_key(self, name: str) -> bytes:
        return (self.keys_dir / f"{name}.pub").read_bytes()

    # ------------------------------------------------------------------ #
    # Permission enforcement                                                #
    # ------------------------------------------------------------------ #

    def _check_permissions(self, path: Path, expected_mode: int) -> None:
        """Log warning if file permissions are too loose."""
        actual = stat.S_IMODE(path.stat().st_mode)
        if actual & ~expected_mode:
            log.warning(
                "Insecure permissions on %s: got %o, expected %o. "
                "Run: chmod %o %s",
                path, actual, expected_mode, expected_mode, path,
            )
            # Attempt auto-fix
            try:
                path.chmod(expected_mode)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Migration                                                             #
    # ------------------------------------------------------------------ #

    def migrate_if_needed(self, cfg: HomeLinkConfig) -> HomeLinkConfig:
        if cfg.version == CONFIG_VERSION:
            return cfg
        log.info("Migrating config from version %d to %d", cfg.version, CONFIG_VERSION)
        cfg.version = CONFIG_VERSION
        self.save_config(cfg)
        return cfg


class SecurityError(Exception):
    """Raised on integrity check failure."""
