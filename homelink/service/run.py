"""
HomeLink service entry point.
Called by systemd: python -m homelink.service.run

SA-01 fix: password loaded from kernel keyring, never from plaintext file.
"""

import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("homelink")


def main():
    config_dir = Path(os.environ.get("HOMELINK_CONFIG_DIR", Path.home() / ".homelink"))

    if not (config_dir / "config.json").exists():
        log.error("HomeLink not initialized. Run: python init.py")
        sys.exit(1)

    # SA-01: load from kernel keyring, never from plaintext file
    from homelink.service.keystore import get_password_for_service
    password = get_password_for_service()

    if not password:
        # Interactive fallback (first boot after reboot when keyring empty)
        if sys.stdin.isatty():
            try:
                password = getpass.getpass("HomeLink master password: ")
            except (EOFError, KeyboardInterrupt):
                log.error("No password provided")
                sys.exit(1)
        else:
            log.error(
                "No password in keyring and no interactive terminal. "
                "Run 'homelink unlock' to load password into keyring."
            )
            sys.exit(1)

    if not password:
        log.error("Empty password — cannot start")
        sys.exit(1)

    from homelink.service.daemon import HomeLinkDaemon
    daemon = HomeLinkDaemon(config_dir=config_dir, password=password)

    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        log.info("Interrupted")
    except Exception as e:
        log.exception("Daemon crashed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
