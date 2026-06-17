"""
HomeLink Keystore
==================
Secure password storage using Linux kernel user keyring.

Fixes SA-01: replaces plaintext ~/.homelink/.svc_pwd with kernel keyring.
The password NEVER touches the filesystem after init.

Fallback chain (in order):
1. Linux kernel keyring (keyctl) — preferred, no filesystem touch
2. systemd-creds encrypted credential file
3. Interactive prompt (for first boot after reboot when keyring empty)

The kernel keyring is user-scoped (@u) and cleared on logout/reboot,
meaning the password must be re-entered after each reboot
(or persisted via a more durable mechanism like TPM2).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

_KEYRING_KEY  = "homelink:master"
_KEYRING_TYPE = "user"
_KEYRING_RING = "@u"   # user keyring — cleared on logout


def store_password(password: str) -> bool:
    """
    Store password in Linux kernel user keyring.
    Returns True on success, False if keyctl unavailable.
    """
    try:
        r = subprocess.run(
            ["keyctl", "add", _KEYRING_TYPE, _KEYRING_KEY, password, _KEYRING_RING],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            log.debug("Password stored in kernel keyring")
            return True
        log.warning("keyctl add failed: %s", r.stderr.strip())
        return False
    except FileNotFoundError:
        log.debug("keyctl not available")
        return False
    except Exception as e:
        log.warning("keyctl error: %s", type(e).__name__)
        return False


def load_password() -> str:
    """
    Load password from kernel keyring.
    Returns empty string if not available.
    """
    try:
        r = subprocess.run(
            ["keyctl", "print", f"%{_KEYRING_TYPE}:{_KEYRING_KEY}"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return r.stdout.strip()
        return ""
    except Exception:
        return ""


def load_password_from_cred() -> str:
    """
    Load password from systemd credential (LoadCredentialEncrypted).
    See: systemd.exec(5) — CREDENTIALS_DIRECTORY.
    """
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not cred_dir:
        return ""
    cred_file = Path(cred_dir) / "homelink-master"
    if cred_file.exists():
        try:
            return cred_file.read_text().strip()
        except Exception:
            return ""
    return ""


def clear_password() -> None:
    """Remove password from kernel keyring (e.g., on logout/revocation)."""
    try:
        subprocess.run(
            ["keyctl", "purge", _KEYRING_TYPE, _KEYRING_KEY],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


def get_password_for_service() -> str:
    """
    Master function for service startup password retrieval.

    Priority:
    1. Kernel keyring (set at init time or previous service start)
    2. systemd credentials (if configured)
    3. Empty (caller must prompt or fail)
    """
    pwd = load_password()
    if pwd:
        return pwd
    pwd = load_password_from_cred()
    if pwd:
        # Store in keyring for faster subsequent access
        store_password(pwd)
        return pwd
    return ""
