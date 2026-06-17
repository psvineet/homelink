#!/usr/bin/env bash
# =============================================================================
# HomeLink — Installation Script
# =============================================================================
# Supports:
#   - Fedora/RHEL/CentOS   (dnf)
#   - Debian/Ubuntu/Mint   (apt)
#   - Arch Linux           (pacman)
#   - Termux (Android)     (pkg)  — client-only, no systemd
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/psvineet/homelink/main/install.sh | bash
#   ./install.sh              # full install (laptop/server)
#   ./install.sh --client     # client-only (Termux / secondary device)
#   ./install.sh --uninstall  # remove everything
# =============================================================================

set -euo pipefail

REPO_URL="https://github.com/psvineet/homelink"
REPO_RAW="https://raw.githubusercontent.com/psvineet/homelink/main"
DEFAULT_INSTALL_DIR="${HOME}/homelink"

# ── colours (safe — defined before any output) ───────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

ok()     { echo -e "${GREEN}✓${RESET} $*"; }
info()   { echo -e "${BLUE}→${RESET} $*"; }
warn()   { echo -e "${YELLOW}⚠${RESET} $*"; }
die()    { echo -e "${RED}✗ ERROR:${RESET} $*" >&2; exit 1; }
header() { echo -e "\n${BOLD}── $* ──────────────────────────────────────${RESET}"; }

# ── curl-pipe detection ───────────────────────────────────────────────────────
# When piped through bash: BASH_SOURCE[0] is unset or literally "bash"
# We must download the repo first, then re-exec the real install.sh
_is_curl_pipe() {
    [[ "${BASH_SOURCE[0]:-bash}" == "bash" ]] || \
    [[ "${BASH_SOURCE[0]:-}" == "" ]] || \
    [[ "${BASH_SOURCE[0]:-}" == "/dev/stdin" ]]
}

if _is_curl_pipe; then
    echo -e "${BOLD}[HomeLink] Downloading repository...${RESET}"
    INSTALL_DIR="$DEFAULT_INSTALL_DIR"

    # Ensure git or curl+unzip available
    if command -v git &>/dev/null; then
        if [[ -d "$INSTALL_DIR/.git" ]]; then
            echo "→ Updating existing clone..."
            git -C "$INSTALL_DIR" pull --quiet --ff-only 2>/dev/null || true
        else
            [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
            echo "→ Cloning ${REPO_URL}..."
            git clone --quiet --depth=1 "$REPO_URL" "$INSTALL_DIR"
        fi
    else
        # No git — install it first, then clone
        echo "→ git not found — installing..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y -q git
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y -q git
        elif command -v pacman &>/dev/null; then
            sudo pacman -Sy --noconfirm git
        elif command -v pkg &>/dev/null; then
            pkg install -y git
        else
            # Last resort: download zip
            echo "→ No package manager found — downloading zip..."
            TMP_ZIP=$(mktemp /tmp/homelink-XXXXXX.zip)
            curl -fsSL "${REPO_URL}/archive/refs/heads/main.zip" -o "$TMP_ZIP"
            TMP_DIR=$(mktemp -d /tmp/homelink-extract-XXXXXX)
            unzip -q "$TMP_ZIP" -d "$TMP_DIR"
            [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
            mv "$TMP_DIR/homelink-main" "$INSTALL_DIR"
            rm -f "$TMP_ZIP"; rm -rf "$TMP_DIR"
        fi
        if command -v git &>/dev/null; then
            [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
            git clone --quiet --depth=1 "$REPO_URL" "$INSTALL_DIR"
        fi
    fi

    [[ -f "$INSTALL_DIR/install.sh" ]] || die "Repo download failed — $INSTALL_DIR/install.sh not found"
    chmod +x "$INSTALL_DIR/install.sh"
    echo "→ Running installer from $INSTALL_DIR..."
    exec bash "$INSTALL_DIR/install.sh" "$@"
    exit 0
fi

# ── from here: running as a real file (not curl pipe) ────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── args ─────────────────────────────────────────────────────────────────────
CLIENT_ONLY=false
UNINSTALL=false
for arg in "$@"; do
    case "$arg" in
        --client)    CLIENT_ONLY=true ;;
        --uninstall) UNINSTALL=true   ;;
        --help|-h)
            echo "Usage: $0 [--client] [--uninstall]"
            echo "  (no flags)    Full install with systemd service"
            echo "  --client      Install homectl client only (Termux / secondary device)"
            echo "  --uninstall   Remove HomeLink completely"
            exit 0 ;;
        *) warn "Unknown option: $arg" ;;
    esac
done

# ── detect environment ────────────────────────────────────────────────────────
IS_TERMUX=false
IS_LINUX=false
PKG_MGR=""

detect_env() {
    if [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d "/data/data/com.termux" ]]; then
        IS_TERMUX=true
        PKG_MGR="pkg"
        CLIENT_ONLY=true
        info "Termux detected — installing client only"
        return
    fi

    IS_LINUX=true

    if command -v dnf    &>/dev/null; then PKG_MGR="dnf"
    elif command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
    else warn "Package manager not detected — install Python 3.11+ manually"
    fi
}

# ── uninstall ─────────────────────────────────────────────────────────────────
do_uninstall() {
    header "Uninstalling HomeLink"
    if command -v systemctl &>/dev/null; then
        systemctl --user stop homelink    2>/dev/null || true
        systemctl --user disable homelink 2>/dev/null || true
        rm -f "${HOME}/.config/systemd/user/homelink.service"
        systemctl --user daemon-reload    2>/dev/null || true
        ok "systemd service removed"
    fi
    VENV="${HOME}/.venv/homelink"
    if [[ -d "$VENV" ]]; then
        rm -rf "$VENV"
        ok "Virtual environment removed"
    fi
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
        [[ -f "$rc" ]] && sed -i '/# HomeLink/d;/venv\/homelink/d' "$rc" 2>/dev/null || true
    done
    warn "Config/keys in ~/.homelink NOT removed. To wipe: rm -rf ~/.homelink"
    ok "HomeLink uninstalled"
}

# ── pick best python ──────────────────────────────────────────────────────────
pick_python() {
    for py in python3.13 python3.12 python3.11 python3.14 python3; do
        if command -v "$py" &>/dev/null; then
            if "$py" -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" 2>/dev/null; then
                echo "$py"; return
            fi
        fi
    done
    echo ""
}

# ── install system deps ───────────────────────────────────────────────────────
install_system_deps() {
    header "System Dependencies"

    PYTHON=$(pick_python)

    if [[ "$IS_TERMUX" == true ]]; then
        info "Updating Termux packages..."
        pkg update -y -q
        pkg install -y python python-pip openssl libsodium 2>/dev/null || true
        ok "Termux packages ready"
        return
    fi

    if [[ -z "$PYTHON" ]]; then
        info "Installing Python 3.11+..."
        case "$PKG_MGR" in
            dnf)    sudo dnf install -y python3.11 python3.11-pip python3.11-venv ;;
            apt)    sudo apt-get update -q
                    sudo apt-get install -y python3.11 python3.11-venv python3-pip ;;
            pacman) sudo pacman -Sy --noconfirm python python-pip ;;
        esac
        PYTHON=$(pick_python)
        [[ -z "$PYTHON" ]] && die "Could not install Python 3.11+"
    else
        local VER; VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        ok "Python $VER found"
    fi

    # Ensure python3-venv is available (Debian/Ubuntu ship it separately)
    if [[ "$PKG_MGR" == "apt" ]]; then
        local PY_VER; PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if ! "$PYTHON" -c "import venv" &>/dev/null; then
            info "Installing python${PY_VER}-venv..."
            sudo apt-get install -y "python${PY_VER}-venv" 2>/dev/null || \
                sudo apt-get install -y python3-venv
        fi
    fi

    # keyutils — optional, for kernel keyring
    if ! command -v keyctl &>/dev/null; then
        info "Installing keyutils (kernel keyring support)..."
        case "$PKG_MGR" in
            dnf)    sudo dnf install -y keyutils    2>/dev/null || true ;;
            apt)    sudo apt-get install -y keyutils 2>/dev/null || true ;;
            pacman) sudo pacman -Sy --noconfirm keyutils 2>/dev/null || true ;;
        esac
    fi
}

# ── remove broken old service ─────────────────────────────────────────────────
repair_service() {
    local UNIT="${HOME}/.config/systemd/user/homelink.service"
    if [[ -f "$UNIT" ]]; then
        systemctl --user stop homelink    2>/dev/null || true
        systemctl --user disable homelink 2>/dev/null || true
        rm -f "$UNIT"
        systemctl --user daemon-reload    2>/dev/null || true
        info "Removed old service unit (will be reinstalled clean)"
    fi
}

# ── install homelink ──────────────────────────────────────────────────────────
install_homelink() {
    header "Installing HomeLink"

    VENV="${HOME}/.venv/homelink"
    PYTHON=$(pick_python)
    [[ -z "$PYTHON" ]] && die "No suitable Python found"

    info "Using Python: $($PYTHON --version)"

    if [[ "$IS_TERMUX" == true ]]; then
        info "Installing dependencies..."
        pip install --quiet --upgrade pip setuptools wheel
        pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
        info "Installing HomeLink package..."
        pip install --quiet "$SCRIPT_DIR"
        ok "HomeLink installed (Termux)"
        return
    fi

    # Remove stale venv if Python version changed
    if [[ -d "$VENV" ]]; then
        local VENV_PY; VENV_PY=$("$VENV/bin/python" --version 2>/dev/null || echo "")
        local SYS_PY; SYS_PY=$("$PYTHON" --version 2>/dev/null || echo "")
        if [[ "$VENV_PY" != "$SYS_PY" ]]; then
            info "Removing stale venv (Python version changed)..."
            rm -rf "$VENV"
        fi
    fi

    if [[ ! -d "$VENV" ]]; then
        info "Creating virtual environment: $VENV"
        "$PYTHON" -m venv "$VENV"
        ok "Virtual environment created"
    else
        info "Reusing existing venv: $VENV"
    fi

    # CRITICAL: upgrade pip+setuptools inside venv before anything else
    # (fixes BackendUnavailable: setuptools.backends.legacy on Python 3.14)
    info "Upgrading pip and setuptools inside venv..."
    "$VENV/bin/pip" install --quiet --upgrade pip setuptools wheel
    ok "pip + setuptools upgraded"

    info "Installing Python dependencies..."
    "$VENV/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
    ok "Dependencies installed"

    info "Installing HomeLink package..."
    "$VENV/bin/pip" install --quiet "$SCRIPT_DIR"
    ok "HomeLink installed"

    [[ -f "$VENV/bin/homelink" ]] || die "homelink binary missing after install"
    ok "Entry points: $VENV/bin/homelink  $VENV/bin/homectl"
}

# ── setup PATH ────────────────────────────────────────────────────────────────
setup_path() {
    header "Configuring PATH"
    VENV="${HOME}/.venv/homelink"
    local SHELL_NAME; SHELL_NAME=$(basename "${SHELL:-bash}")

    local RC_FILES=()
    [[ "$SHELL_NAME" == "zsh"  ]] && RC_FILES+=("${HOME}/.zshrc")
    [[ "$SHELL_NAME" == "bash" ]] && RC_FILES+=("${HOME}/.bashrc")
    RC_FILES+=("${HOME}/.bashrc")   # always include .bashrc as fallback

    for RC in "${RC_FILES[@]}"; do
        [[ -f "$RC" ]] || touch "$RC"
        if grep -q "venv/homelink/bin" "$RC" 2>/dev/null; then
            ok "PATH already set in $RC"
        else
            printf '\n# HomeLink\nexport PATH="%s/bin:$PATH"\n' "$VENV" >> "$RC"
            ok "Added PATH to $RC"
        fi
    done

    export PATH="${VENV}/bin:${PATH}"
    ok "PATH active in current session"
}

# ── run init wizard ───────────────────────────────────────────────────────────
run_init() {
    header "HomeLink Setup Wizard"
    VENV="${HOME}/.venv/homelink"
    local INIT_PY="$SCRIPT_DIR/init.py"
    [[ -f "$INIT_PY" ]] || die "init.py not found in $SCRIPT_DIR"

    if [[ "$IS_TERMUX" == true ]]; then
        python3 "$INIT_PY"
    else
        "$VENV/bin/python" "$INIT_PY"
    fi
}

# ── verify ────────────────────────────────────────────────────────────────────
verify_install() {
    header "Verifying Installation"
    VENV="${HOME}/.venv/homelink"

    if [[ -f "$VENV/bin/homelink" ]]; then
        ok "homelink: $VENV/bin/homelink"
    else
        warn "homelink binary not found — install may have failed"
    fi

    if [[ -f "$VENV/bin/homectl" ]]; then
        ok "homectl:  $VENV/bin/homectl"
    fi

    if command -v homelink &>/dev/null; then
        ok "homelink available in PATH"
    else
        warn "homelink not in PATH yet — run: source ~/.bashrc"
        echo "    (or open a new terminal)"
    fi
}

# ── banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║         HomeLink Installer v1.0.0            ║"
echo "║  Secure remote access — no VPS, no cost      ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

detect_env

if [[ "$UNINSTALL" == true ]]; then
    do_uninstall
    exit 0
fi

install_system_deps
repair_service
install_homelink

[[ "$IS_TERMUX" == false ]] && setup_path

verify_install

echo ""
echo -e "${BOLD}Installation complete!${RESET}"
echo ""

# read fails when stdin is a pipe (curl | bash scenario that re-exec'd)
# so guard it
if [[ -t 0 ]]; then
    read -r -p "Run setup wizard now? [Y/n]: " RUN_WIZARD
    if [[ "${RUN_WIZARD:-Y}" =~ ^[Yy]?$ ]]; then
        run_init
    else
        echo ""
        echo "Run setup later:  $SCRIPT_DIR/init.py"
        echo "Or:               homelink --help"
    fi
else
    echo "Run setup:  bash ${SCRIPT_DIR}/init.py"
    echo "Or:         source ~/.bashrc && homelink --help"
fi
