<div align="center">

# 🔗 HomeLink

**Secure remote access to your home machine — no static IP, no VPS, no monthly cost.**

Uses Telegram as an encrypted relay. Works from anywhere, including mobile via Termux.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Termux-lightgrey)](#)

</div>

---

## Install

### One-line install (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/psvineet/homelink/main/install.sh | bash
```

### Or clone and run

```bash
git clone https://github.com/psvineet/homelink
cd homelink
chmod +x install.sh && ./install.sh
```

### Termux (Android)

```bash
curl -fsSL https://raw.githubusercontent.com/psvineet/homelink/main/install.sh | bash
```

Auto-detects Termux — installs client only, no systemd needed.

### Options

```bash
./install.sh --client     # client only (no daemon, no systemd)
./install.sh --uninstall  # full removal
```

---

## Setup

The installer runs the setup wizard automatically. You need two things from Telegram:

**1. Bot token** — message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token

**2. Your chat ID** — message [@userinfobot](https://t.me/userinfobot) → send `/start` → copy the number

> ⚠️ **Send at least one message to your bot before running setup**, otherwise your chat ID won't be reachable.

---

## How It Works

```
  [Termux / mobile]  ──→  Telegram Bot  ──→  [Home machine daemon]
         homectl                                    homelink
   (sends encrypted                          (decrypts, executes,
      command)                                   sends reply)
```

- All traffic is **end-to-end encrypted** (NaCl X25519 + XSalsa20-Poly1305)
- Telegram is just the relay — it sees only ciphertext
- No port forwarding, no dynamic DNS, no VPS needed
- Keys never leave your device unencrypted

---

## Usage

### On your home machine (daemon)

```bash
homelink start          # start daemon
homelink stop           # stop daemon
homelink restart        # restart
homelink status         # check status
homelink logs           # tail logs
homelink devices        # list paired devices
homelink reconfigure-telegram   # fix Telegram config
```

### From any device (client)

```bash
homectl ls ~/Documents          # list files
homectl get ~/notes.txt .       # download file
homectl put ./report.pdf ~/     # upload file
homectl exec "df -h"            # run command
homectl exec "uptime"
```

---

## Requirements

| | Minimum |
|---|---|
| Python | 3.11+ |
| OS | Linux (systemd optional) |
| Internet | Yes (Telegram API) |
| Telegram | Bot token + chat ID |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `homelink: command not found` after install | `source ~/.bashrc` or open a new terminal |
| Telegram verification fails | Send `/start` to your bot first, then recheck chat ID via `@userinfobot` |
| `Service: stopped` in status | Run `homelink start` then `journalctl --user -u homelink -n 20` |
| No transport / daemon not running | Configure Telegram: `homelink reconfigure-telegram` |
| `status=218/CAPABILITIES` in journal | Re-run `./install.sh` — fixed in this version |
| Password prompt on every restart | `sudo dnf install keyutils` (or `apt install keyutils`) |

---

## Project Structure

```
homelink/
├── install.sh              ← one-line installer
├── init.py                 ← setup wizard
├── pyproject.toml
├── requirements.txt
└── homelink/
    ├── cli/                ← homelink + homectl commands
    ├── config/             ← config manager
    ├── crypto/             ← NaCl keys, Argon2 KDF, session encryption
    ├── service/            ← daemon, systemd installer, kernel keyring
    └── transport/
        └── telegram/       ← Telegram relay transport
```

---

## Security

- **Keys at rest**: AES-256-GCM encrypted, Argon2id KDF
- **Transport**: NaCl X25519 key exchange, XSalsa20-Poly1305
- **Password**: stored in Linux kernel keyring (`keyctl`), never on disk
- **Device auth**: pairing required before any command is accepted
- **Telegram relay**: sees only ciphertext, no plaintext ever leaves your device


---

## License

MIT — see [LICENSE](LICENSE)
