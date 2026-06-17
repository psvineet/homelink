#!/usr/bin/env python3
"""
HomeLink Installer — Hardened
==============================

Security changes vs original
-----------------------------
- SA-01  : Password stored in kernel keyring (not plaintext file)
- SA-14  : Password strength validated before acceptance
- CRYPTO : Warns if entropy appears low (first boot)
- FIX    : Telegram verification uses correct API call with chat_id check
- FIX    : pyproject.toml build backend fixed for Python 3.14 compat
"""

import asyncio
import getpass
import os
import platform
import sys
from pathlib import Path


def _check_python():
    if sys.version_info < (3, 11):
        print("ERROR: HomeLink requires Python 3.11+")
        sys.exit(1)


def _check_deps():
    missing = []
    for pkg in ["nacl", "argon2", "cryptography", "click", "rich", "aiohttp", "aiofiles"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Missing packages: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)


def _banner():
    print("""
╔══════════════════════════════════════════════╗
║         HomeLink Installation Wizard         ║
║  Secure remote access — no VPS, no cost      ║
╚══════════════════════════════════════════════╝
""")


def _ask(prompt: str, default: str = "") -> str:
    disp = f" [{default}]" if default else ""
    while True:
        val = input(f"{prompt}{disp}: ").strip()
        if val:
            return val
        if default:
            return default
        print("  (required)")


def _ask_password() -> str:
    """Ask for master password with strength validation."""
    from homelink.crypto.kdf import validate_password_strength
    while True:
        pwd = getpass.getpass("Master password (encrypts your private keys): ")
        issues = validate_password_strength(pwd)
        if issues:
            print("  Password does not meet requirements:")
            for issue in issues:
                print(f"    • {issue}")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pwd != confirm:
            print("  Passwords do not match")
            continue
        return pwd


def main():
    _check_python()
    _check_deps()
    _banner()

    print("This wizard will set up HomeLink on this machine.\n")

    device_name = _ask("Device name", default=platform.node() or "home-server")

    print("\n── Encryption ──────────────────────────────")
    print("Password requirements: 12+ chars, upper, lower, digit.")
    print("Your private keys are encrypted with this password.\n")
    password = _ask_password()

    print("\n── Telegram Bot ─────────────────────────────")
    print("1. Message @BotFather on Telegram: /newbot → copy the bot token")
    print("2. Message @userinfobot on Telegram → copy your numeric Chat ID")
    print("   (Chat ID looks like: 123456789 or -100123456789 for groups)\n")

    use_telegram = input("Set up Telegram now? [Y/n]: ").strip().lower() != "n"
    bot_token = ""
    chat_id   = ""
    if use_telegram:
        bot_token = _ask("Bot Token (from @BotFather, format: 123456:ABC-DEF...)")
        chat_id   = _ask("Chat ID (numeric, from @userinfobot)")
        # Basic validation
        if ":" not in bot_token:
            print("  ⚠ Bot token looks wrong — expected format: 123456789:ABC-DEF...")
        if not chat_id.lstrip("-").isdigit():
            print("  ⚠ Chat ID should be numeric (e.g. 123456789)")

    print("\n── Generating Keys ──────────────────────────")
    from homelink.crypto.keys import DeviceIdentity
    from homelink.crypto.session import encrypt_private_key
    identity = DeviceIdentity.generate(name=device_name)
    print(f"  Device ID:   {identity.device_id}")
    print(f"  Fingerprint: {identity.fingerprint}")

    print("\n── Creating Configuration ───────────────────")
    config_dir = Path.home() / ".homelink"
    from homelink.config.manager import ConfigManager, HomeLinkConfig, TelegramConfig
    mgr = ConfigManager(config_dir)
    mgr.ensure_dirs()

    # Encrypt and store private keys
    enc_signing = encrypt_private_key(identity.signing.private_bytes, password)
    enc_dh      = encrypt_private_key(identity.dh.private_bytes, password)
    mgr.save_encrypted_key("signing", enc_signing)
    mgr.save_encrypted_key("dh",      enc_dh)
    mgr.save_public_key("signing",    identity.signing.public_bytes)
    mgr.save_public_key("dh",         identity.dh.public_bytes)
    print(f"  Keys saved (encrypted) → {config_dir}/keys/")

    from homelink.crypto.kdf import hash_password
    cfg = HomeLinkConfig()
    cfg.device_name   = device_name
    cfg.device_id     = identity.device_id
    cfg.password_hash = hash_password(password)
    cfg.telegram.enabled   = use_telegram and bool(bot_token and chat_id)
    cfg.telegram.bot_token = bot_token
    cfg.telegram.chat_id   = chat_id
    cfg.logging.log_dir    = str(config_dir / "logs")
    mgr.save_config(cfg)
    print(f"  Config saved → {config_dir}/config.json")

    # SA-01: store password in kernel keyring (NOT filesystem)
    print("\n── Storing Password Securely ────────────────")
    from homelink.service.keystore import store_password
    stored = store_password(password)
    if stored:
        print("  ✓ Password stored in Linux kernel keyring (no plaintext on disk)")
    else:
        print("  ⚠ keyctl unavailable — you will be prompted at each service start")
        print("    Install keyutils: sudo dnf install keyutils  # or apt install keyutils")

    # Register this device as self (approved, administrator)
    self_info = {**identity.public_info(), "approved": True, "role": "administrator"}
    mgr.add_device(self_info)

    print("\n── Installing Service ───────────────────────")
    from homelink.service.installer import ServiceInstaller
    installer = ServiceInstaller(config_dir)
    installed = installer.install()
    if installed:
        print("  ✓ systemd user service installed (hardened)")
        started = installer.start()
        if started:
            print("  ✓ Service started")
        else:
            print("  ⚠ Start with: homelink start")
    else:
        print("  ⚠ Service install failed — run manually: python -m homelink.service.run")

    if use_telegram and bot_token and chat_id:
        print("\n── Verifying Telegram ───────────────────────")
        ok, detail = asyncio.run(_check_telegram(bot_token, chat_id))
        if ok:
            print(f"  ✓ {detail}")
        else:
            print(f"  ✗ {detail}")
            print("\n  Common fixes:")
            print("  • Token: must be exactly as given by @BotFather (no spaces)")
            print("  • Chat ID: get it from @userinfobot (send /start to that bot)")
            print("  • Make sure you sent at least one message TO your bot first")
            print("  • Run: homelink reconfigure-telegram  to fix later")

    print(f"""
╔══════════════════════════════════════════════╗
║            Installation Complete!            ║
╠══════════════════════════════════════════════╣
║  Device ID:  {identity.device_id:<30} ║
║  Name:       {device_name:<30} ║
╠══════════════════════════════════════════════╣
║  Commands:                                   ║
║    homelink status      daemon status        ║
║    homelink logs        view logs            ║
║    homectl ls ~         list remote files    ║
║    homectl get <f>      download file        ║
║    homectl exec uptime  run command          ║
╚══════════════════════════════════════════════╝
""")


async def _check_telegram(bot_token: str, chat_id: str) -> tuple[bool, str]:
    """
    Verify Telegram bot token AND that the chat_id is reachable.
    Returns (success, message).

    Two-step check:
    1. getMe  — validates the token
    2. sendMessage with a test message — validates chat_id is reachable
    """
    import aiohttp

    base = f"https://api.telegram.org/bot{bot_token}"

    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: validate token via getMe
            async with session.get(
                f"{base}/getMe",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    err = data.get("description", "unknown error")
                    return False, f"Token rejected by Telegram: {err}"
                bot_name = data["result"].get("username", "unknown")

            # Step 2: send a test message to validate chat_id
            async with session.post(
                f"{base}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": (
                        "🔗 HomeLink connected successfully!\n"
                        f"Device setup complete. Bot: @{bot_name}"
                    ),
                    "disable_notification": True,
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    err = data.get("description", "unknown error")
                    if "chat not found" in err.lower():
                        return False, (
                            f"Bot @{bot_name} OK, but chat_id '{chat_id}' not found.\n"
                            "  Send a message to your bot first, then get your ID from @userinfobot"
                        )
                    if "blocked" in err.lower():
                        return False, f"Bot @{bot_name} OK, but you have blocked the bot. Unblock it."
                    return False, f"Bot @{bot_name} OK, but sendMessage failed: {err}"

        return True, f"Bot @{bot_name} connected and message sent to chat {chat_id}"

    except aiohttp.ClientConnectorError:
        return False, "Network error — check internet connection"
    except asyncio.TimeoutError:
        return False, "Telegram API timed out — check internet connection"
    except Exception as e:
        return False, f"Unexpected error: {type(e).__name__}: {e}"


if __name__ == "__main__":
    main()
