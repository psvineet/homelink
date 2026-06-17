"""
HomeLink Command Executor
==========================
Executes registry-validated commands via async subprocess.
No shell=True anywhere. Absolute executable paths from registry.

Fixes applied
-------------
- SA-03  : Uses resolve_command() → absolute exe path + validated args
- SA-12  : Rate limiting via RateLimiter
- Security: Environment fully sanitized, cwd locked, no implicit privileges
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional

from homelink.commands.permissions import PermissionDenied, PermissionManager
from homelink.core.rate_limiter import EXEC_LIMITER

log = logging.getLogger(__name__)
audit_log = logging.getLogger("homelink.audit")

# Minimal safe environment — no user env vars, no PATH tricks
SAFE_ENV: dict[str, str] = {
    "PATH":    "/usr/local/bin:/usr/bin:/bin",
    "HOME":    "/tmp",
    "LANG":    "en_US.UTF-8",
    "TERM":    "dumb",
    "SHELL":   "/bin/sh",  # set to known value even though shell=False
}

MAX_OUTPUT_BYTES = 1_048_576   # 1 MB per stream


@dataclass
class ExecResult:
    command:     str
    returncode:  int
    stdout:      str
    stderr:      str
    elapsed:     float
    timed_out:   bool = False
    denied:      bool = False
    deny_reason: str  = ""

    def to_dict(self) -> dict:
        return {
            "type":        "exec_result",
            "command":     self.command,
            "returncode":  self.returncode,
            "stdout":      self.stdout,
            "stderr":      self.stderr,
            "elapsed":     round(self.elapsed, 3),
            "timed_out":   self.timed_out,
            "denied":      self.denied,
            "deny_reason": self.deny_reason,
        }


class CommandExecutor:
    """
    Executes permitted commands with timeout, output cap, and audit logging.
    All commands run via registry-resolved absolute paths with no shell.
    """

    def __init__(
        self,
        permissions: PermissionManager,
        max_timeout: int = 60,
        work_dir: str = "/tmp",
    ):
        self._perms      = permissions
        self._max_timeout = max_timeout
        self._work_dir   = work_dir
        self._history: list[dict] = []

    async def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        requester_device_id: str = "unknown",
    ) -> ExecResult:
        """
        Execute a validated command. Returns ExecResult in all cases.
        Rate-limited, audit-logged, no-shell, safe env.
        """
        start = time.monotonic()

        # Rate limit check (SA-12)
        if not EXEC_LIMITER.is_allowed(requester_device_id):
            audit_log.warning(
                "EXEC_RATE_LIMITED device=%s command=%r", requester_device_id, command
            )
            return ExecResult(
                command=command, returncode=-1, stdout="", stderr="",
                elapsed=0.0, denied=True,
                deny_reason="rate limit exceeded (max 10 exec/minute per device)",
            )

        # Permission + argument resolution (SA-03)
        try:
            exe, argv = self._perms.resolve_command(command)
        except PermissionDenied as e:
            audit_log.warning(
                "EXEC_DENIED device=%s command=%r reason=%s",
                requester_device_id, command, str(e),
            )
            return ExecResult(
                command=command, returncode=-1, stdout="", stderr="",
                elapsed=0.0, denied=True, deny_reason=str(e),
            )

        effective_timeout = min(timeout or self._max_timeout, self._max_timeout)

        audit_log.info(
            "EXEC_START device=%s exe=%r argv=%r timeout=%ds",
            requester_device_id, exe, argv, effective_timeout,
        )

        timed_out = False
        try:
            # NEVER shell=True; use absolute exe path from registry
            proc = await asyncio.create_subprocess_exec(
                exe, *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._work_dir,
                env=SAFE_ENV,
                start_new_session=True,   # isolate process group for clean kill
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=float(effective_timeout)
                )
            except asyncio.TimeoutError:
                timed_out = True
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                stdout_b, stderr_b = await proc.communicate()

            returncode = proc.returncode if proc.returncode is not None else -1
            stdout = stdout_b[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            stderr = stderr_b[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        except FileNotFoundError:
            returncode = 127
            stdout = ""
            stderr = f"Executable not found: {exe}"
        except PermissionError:
            returncode = 126
            stdout = ""
            stderr = f"Permission denied: {exe}"
        except Exception as e:
            returncode = -1
            stdout = ""
            stderr = f"Execution error: {type(e).__name__}"
            log.error("Unexpected exec error for %r: %s", command, e)

        elapsed = time.monotonic() - start
        result = ExecResult(
            command=command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            elapsed=elapsed,
            timed_out=timed_out,
        )

        audit_log.info(
            "EXEC_DONE device=%s exe=%r rc=%d elapsed=%.2fs timed_out=%s",
            requester_device_id, exe, returncode, elapsed, timed_out,
        )

        self._history.append({
            "device":    requester_device_id,
            "command":   command,
            "exe":       exe,
            "rc":        returncode,
            "elapsed":   round(elapsed, 3),
            "ts":        time.time(),
        })
        if len(self._history) > 500:
            self._history = self._history[-250:]

        return result

    def get_history(self, limit: int = 50) -> list[dict]:
        return list(self._history[-limit:])
