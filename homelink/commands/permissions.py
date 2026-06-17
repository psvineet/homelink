"""
HomeLink Command Permission System
====================================
Fixes SA-03: Replaces prefix-match allowlist with exact command registry.

Design
------
- Command registry: name → (absolute_path, fixed_args, arg_validator | None)
- No user-supplied strings reach the shell (shell=False enforced in executor)
- Argument validators enforce exact argument shapes
- Path arguments restricted to allowed roots
- Restricted base commands permanently blocked regardless of registry

RBAC integration
----------------
- viewer    : read-only commands (uptime, df, free, hostname, date, uname, id, whoami)
- operator  : viewer + ls (within home), systemctl status, journalctl
- administrator : operator + echo (for testing)
"""

from __future__ import annotations

import logging
import re
import shlex
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)


class PermissionDenied(Exception):
    """Raised when command is not permitted."""


# ---------------------------------------------------------------------------
# Argument validators
# ---------------------------------------------------------------------------

def _no_args(args: list[str]) -> bool:
    return len(args) == 0


def _validate_ls(args: list[str], allowed_root: str) -> bool:
    """ls: zero or one path argument, within allowed_root."""
    if len(args) == 0:
        return True
    if len(args) > 1:
        return False
    try:
        p = Path(args[0]).expanduser().resolve()
        root = Path(allowed_root).expanduser().resolve()
        return str(p).startswith(str(root))
    except Exception:
        return False


_UNIT_RE = re.compile(r"^[a-zA-Z0-9._@-]{1,64}$")

def _validate_systemctl_status(args: list[str]) -> bool:
    """systemctl status <unit> — unit name must be safe."""
    if len(args) != 1:
        return False
    return bool(_UNIT_RE.match(args[0]))


_ECHO_MAX = 200

def _validate_echo(args: list[str]) -> bool:
    """echo: exactly one argument, max 200 chars, no shell metacharacters."""
    if len(args) != 1:
        return False
    msg = args[0]
    if len(msg) > _ECHO_MAX:
        return False
    # Block shell metacharacters that might confuse callers
    if any(c in msg for c in "$`\\;|&><(){}"):
        return False
    return True


_JCTL_N_RE = re.compile(r"^\d{1,5}$")  # 1–99999

def _validate_journalctl(args: list[str]) -> bool:
    """`journalctl -n <N>` — N must be 1–99999."""
    if len(args) == 0:
        return True
    if len(args) == 2 and args[0] == "-n":
        return bool(_JCTL_N_RE.match(args[1]))
    return False


# ---------------------------------------------------------------------------
# Command registry
# {name: (absolute_exe, fixed_args, validator_or_none, min_role)}
# ---------------------------------------------------------------------------

ALLOWED_ROOT = str(Path.home())

_REGISTRY: dict[str, tuple[str, list[str], Callable | None, str]] = {
    # name           exe                  fixed_args  validator              min_role
    "uptime":   ("/usr/bin/uptime",   [],         _no_args,               "viewer"),
    "df":       ("/usr/bin/df",       ["-h"],     _no_args,               "viewer"),
    "free":     ("/usr/bin/free",     ["-h"],     _no_args,               "viewer"),
    "hostname": ("/usr/bin/hostname", [],         _no_args,               "viewer"),
    "date":     ("/usr/bin/date",     [],         _no_args,               "viewer"),
    "uname":    ("/usr/bin/uname",    ["-a"],     _no_args,               "viewer"),
    "id":       ("/usr/bin/id",       [],         _no_args,               "viewer"),
    "whoami":   ("/usr/bin/whoami",   [],         _no_args,               "viewer"),
    "ls":       ("/usr/bin/ls",       ["-la", "--color=never"],
                                                  lambda a: _validate_ls(a, ALLOWED_ROOT),
                                                                          "operator"),
    "systemctl":("/usr/bin/systemctl",["status"], _validate_systemctl_status,
                                                                          "operator"),
    "journalctl":("/usr/bin/journalctl", [],      _validate_journalctl,   "operator"),
    "echo":     ("/usr/bin/echo",     [],         _validate_echo,         "administrator"),
}

# These commands can NEVER be executed remotely, regardless of registry
_PERMANENT_BLOCK: frozenset[str] = frozenset({
    "rm", "rmdir", "dd", "mkfs", "fdisk", "parted", "mkdosfs",
    "shutdown", "reboot", "halt", "poweroff", "systemctl reboot",
    "passwd", "sudo", "su", "doas", "pkexec", "newgrp",
    "chmod", "chown", "chattr", "setfacl",
    "iptables", "ip6tables", "ufw", "nft", "firewall-cmd",
    "curl", "wget", "fetch", "aria2c",
    "nc", "netcat", "ncat", "socat", "nmap",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "nodejs",
    "lua", "tcl", "awk", "gawk", "mawk",
    "bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
    "eval", "exec", "xargs", "env", "printenv",
    "at", "cron", "crontab", "batch",
    "ssh", "scp", "sftp", "rsync",
    "mount", "umount", "losetup", "cryptsetup",
    "insmod", "rmmod", "modprobe", "lsmod",
    "strace", "ltrace", "gdb", "lldb",
    "apt", "apt-get", "yum", "dnf", "pacman", "pip", "pip3",
})

ROLE_HIERARCHY = {"viewer": 0, "operator": 1, "administrator": 2}


class PermissionManager:
    """
    Resolves commands through the registry with RBAC enforcement.
    Deny-by-default: only registry entries are accessible.
    """

    def __init__(self, device_role: str = "viewer"):
        self._role = device_role
        self._role_level = ROLE_HIERARCHY.get(device_role, 0)

    def resolve_command(self, command: str) -> tuple[str, list[str]]:
        """
        Validate command and return (executable_path, full_argv).
        Raises PermissionDenied with reason.
        """
        try:
            parts = shlex.split(command)
        except ValueError as e:
            raise PermissionDenied(f"Malformed command syntax: {e}")

        if not parts:
            raise PermissionDenied("Empty command")

        # Strip any path prefix: /usr/bin/ls → ls
        base_name = Path(parts[0]).name.lower()

        # Permanent block check
        if base_name in _PERMANENT_BLOCK:
            raise PermissionDenied(
                f"Command '{base_name}' is permanently blocked for remote execution"
            )

        # Registry lookup
        if base_name not in _REGISTRY:
            raise PermissionDenied(
                f"Command '{base_name}' is not in the remote execution registry. "
                "Contact administrator to add approved commands."
            )

        exe, fixed_args, validator, min_role = _REGISTRY[base_name]

        # RBAC check
        required_level = ROLE_HIERARCHY.get(min_role, 999)
        if self._role_level < required_level:
            raise PermissionDenied(
                f"Command '{base_name}' requires role '{min_role}'; "
                f"your device role is '{self._role}'"
            )

        # Argument validation
        user_args = parts[1:]
        if validator is None:
            if user_args:
                raise PermissionDenied(
                    f"Command '{base_name}' takes no arguments; got: {user_args!r}"
                )
        else:
            if not validator(user_args):
                raise PermissionDenied(
                    f"Invalid arguments for '{base_name}': {user_args!r}"
                )

        log.debug("Command resolved: %s → %s %s", command, exe, fixed_args + user_args)
        return exe, fixed_args + user_args

    def check(self, command: str) -> None:
        """Alias for resolve_command that discards the result (used by tests)."""
        self.resolve_command(command)

    def is_allowed(self, command: str) -> bool:
        try:
            self.resolve_command(command)
            return True
        except PermissionDenied:
            return False
