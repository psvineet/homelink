"""
HomeLink Service Installer
===========================
Installs the hardened systemd user service.

Fixes SA-16: full systemd hardening applied.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

SERVICE_NAME = "homelink"

# SA-16: Full systemd hardening
SERVICE_TEMPLATE = """\
[Unit]
Description=HomeLink — Secure Remote Access Daemon
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/psvineet/homelink

[Service]
Type=simple
ExecStart={python} -m homelink.service.run
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=120
StartLimitBurst=3

# === Safe hardening (compatible with user services) ===
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={config_dir}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectHostname=true
PrivateDevices=true
NoNewPrivileges=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native

# === Resource limits ===
TasksMax=64
LimitNOFILE=4096

# Environment
Environment=HOMELINK_CONFIG_DIR={config_dir}
Environment=HOME={home_dir}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=homelink

[Install]
WantedBy=default.target
"""


class ServiceInstaller:
    def __init__(self, config_dir: Path):
        self._config_dir = config_dir
        self._unit_dir   = Path.home() / ".config" / "systemd" / "user"
        self._unit_file  = self._unit_dir / f"{SERVICE_NAME}.service"

    def install(self) -> bool:
        self._unit_dir.mkdir(parents=True, exist_ok=True)
        content = SERVICE_TEMPLATE.format(
            python=sys.executable,
            config_dir=str(self._config_dir),
            home_dir=str(Path.home()),
        )
        self._unit_file.write_text(content)
        self._unit_file.chmod(0o644)
        log.info("Service unit written: %s", self._unit_file)
        try:
            self._systemctl("daemon-reload")
            self._systemctl("enable", SERVICE_NAME)
            self._enable_linger()
            return True
        except Exception as e:
            log.error("Service install failed: %s", e)
            return False

    def start(self) -> bool:
        try:
            self._systemctl("start", SERVICE_NAME)
            return True
        except Exception as e:
            log.error("Service start failed: %s", e)
            return False

    def stop(self) -> bool:
        try:
            self._systemctl("stop", SERVICE_NAME)
            return True
        except Exception as e:
            log.error("Service stop: %s", e)
            return False

    def restart(self) -> bool:
        try:
            self._systemctl("restart", SERVICE_NAME)
            return True
        except Exception as e:
            log.error("Service restart: %s", e)
            return False

    def remove(self) -> bool:
        for action in ("stop", "disable"):
            try:
                self._systemctl(action, SERVICE_NAME)
            except Exception:
                pass
        if self._unit_file.exists():
            self._unit_file.unlink()
        try:
            self._systemctl("daemon-reload")
        except Exception:
            pass
        return True

    def status(self) -> dict:
        try:
            r = subprocess.run(
                ["systemctl", "--user", "status", SERVICE_NAME],
                capture_output=True, text=True,
            )
            return {
                "installed": self._unit_file.exists(),
                "active":    "active (running)" in r.stdout,
                "output":    r.stdout,
            }
        except FileNotFoundError:
            return {"installed": False, "active": False, "output": "systemd not available"}

    def is_running(self) -> bool:
        try:
            r = subprocess.run(
                ["systemctl", "--user", "is-active", SERVICE_NAME],
                capture_output=True, text=True,
            )
            return r.stdout.strip() == "active"
        except Exception:
            return False

    def _systemctl(self, *args: str) -> None:
        cmd = ["systemctl", "--user"] + list(args)
        r   = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"systemctl {' '.join(args)}: {r.stderr.strip()}")

    def _enable_linger(self) -> None:
        try:
            user = os.environ.get("USER", "")
            if user:
                subprocess.run(["loginctl", "enable-linger", user], capture_output=True)
                log.info("Lingering enabled for user %s", user)
        except Exception as e:
            log.debug("Could not enable linger: %s", e)
