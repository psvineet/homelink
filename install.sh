#!/usr/bin/env bash
# =============================================================================
# HomeLink — Installation Script
# =============================================================================

REPO_URL="https://github.com/psvineet/homelink"
DEFAULT_INSTALL_DIR="${HOME}/homelink"

# colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

ok()     { echo -e "${GREEN}✓${RESET} $*"; }
info()   { echo -e "${BLUE}→${RESET} $*"; }
warn()   { echo -e "${YELLOW}⚠${RESET} $*"; }
die()    { echo -e "${RED}✗ ERROR:${RESET} $*" >&2; exit 1; }
header() { echo -e "\n${BOLD}── $* ──────────────────────────────────────${RESET}"; }

banner() {
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║         HomeLink Installer v1.0.0            ║"
    echo "║  Secure remote access — no VPS, no cost      ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ── curl-pipe detection ───────────────────────────────────────────────────────
# BASH_SOURCE is unset when piped — use ${BASH_SOURCE[0]-} (default empty)
SELF="${BASH_SOURCE[0]-}"

if [[ -z "$SELF" || "$SELF" == "bash" || "$SELF" == "/dev/stdin" ]]; then
    banner
    info "Curl-install detected — downloading repository..."
    INSTALL_DIR="$DEFAULT_INSTALL_DIR"

    # Install git if missing
    if ! command -v git &>/dev/null; then
        info "Installing git..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y -q git
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y -q git
        elif command -v pacman &>/dev/null; then
            sudo pacman -Sy --noconfirm git
        elif command -v pkg &>/dev/null; then
            pkg install -y git
        else
            die "Cannot install git — please install it manually and re-run"
        fi
    fi

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Updating existing clone at $INSTALL_DIR..."
        git -C "$INSTALL_DIR" pull --quiet --ff-only 2>/dev/null || true
    else
        [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
        info "Cloning $REPO_URL..."
        git clone --quiet --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi

    [[ -f "$INSTALL_DIR/install.sh" ]] || die "Clone failed — install.sh not found in $INSTALL_DIR"
    chmod +x "$INSTALL_DIR/install.sh"
    info "Running installer from $INSTALL_DIR..."
    # Use env -i to get a clean exec, passing args through
    exec bash "$INSTALL_DIR/install.sh" "$@"
fi

# ── running as a real file from here ─────────────────────────────────────────
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$SELF")" && pwd)"

# args
CLIENT_ONLY=false
UNINSTALL=false
for arg in "$@"; do
    case "$arg" in
        --client)    CLIENT_ONLY=true ;;
        --uninstall) UNINSTALL=true ;;
        --help|-h)
            echo "Usage: $0 [--client] [--uninstall]"
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
        info "Termux detected — client-only mode"
        return
    fi
    IS_LINUX=true
    if command -v dnf      &>/dev/null; then PKG_MGR="dnf"
    elif command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
    else warn "Package manager not detected"
    fi
}

# ── pick python ───────────────────────────────────────────────────────────────
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
    [[ -d "${HOME}/.venv/homelink" ]] && rm -rf "${HOME}/.venv/homelink" && ok "venv removed"
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
        [[ -f "$rc" ]] && sed -i '/# HomeLink/d;/venv\/homelink/d' "$rc" 2>/dev/null || true
    done
    warn "Config/keys in ~/.homelink NOT removed. To wipe: rm -rf ~/.homelink"
    ok "HomeLink uninstalled"
}

# ── system deps ───────────────────────────────────────────────────────────────
install_system_deps() {
    header "System Dependencies"

    if [[ "$IS_TERMUX" == true ]]; then
        pkg update -y -q
        pkg install -y python python-pip openssl libsodium 2>/dev/null || true
        ok "Termux packages ready"
        return
    fi

    local PYTHON; PYTHON=$(pick_python)

    if [[ -z "$PYTHON" ]]; then
        info "Installing Python 3.11+..."
        case "$PKG_MGR" in
            dnf) sudo dnf install -y python3.11 python3.11-venv python3-pip ;;
            apt) sudo apt-get update -q
                 sudo apt-get install -y python3.11 python3.11-venv python3-pip ;;
            pacman) sudo pacman -Sy --noconfirm python python-pip ;;
        esac
        PYTHON=$(pick_python)
        [[ -z "$PYTHON" ]] && die "Could not install Python 3.11+"
    else
        local VER; VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        ok "Python $VER found"
    fi

    # Debian/Ubuntu: python3-venv is a separate package
    if [[ "$PKG_MGR" == "apt" ]]; then
        if ! "$PYTHON" -c "import venv" &>/dev/null 2>&1; then
            local PY_VER; PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            info "Installing python${PY_VER}-venv..."
            sudo apt-get install -y "python${PY_VER}-venv" 2>/dev/null || \
                sudo apt-get install -y python3-venv
        fi
    fi

    # keyutils — optional
    if ! command -v keyctl &>/dev/null; then
        info "Installing keyutils..."
        case "$PKG_MGR" in
            dnf)    sudo dnf install -y keyutils    2>/dev/null || true ;;
            apt)    sudo apt-get install -y keyutils 2>/dev/null || true ;;
            pacman) sudo pacman -Sy --noconfirm keyutils 2>/dev/null || true ;;
        esac
    fi
}

# ── repair old broken service ─────────────────────────────────────────────────
repair_service() {
    local UNIT="${HOME}/.config/systemd/user/homelink.service"
    if [[ -f "$UNIT" ]]; then
        systemctl --user stop homelink    2>/dev/null || true
        systemctl --user disable homelink 2>/dev/null || true
        rm -f "$UNIT"
        systemctl --user daemon-reload    2>/dev/null || true
        info "Removed old service unit (will reinstall clean)"
    fi
}

# ── install homelink ──────────────────────────────────────────────────────────
install_homelink() {
    header "Installing HomeLink"

    local PYTHON; PYTHON=$(pick_python)
    [[ -z "$PYTHON" ]] && die "No suitable Python found"
    info "Using Python: $($PYTHON --version)"

    local VENV="${HOME}/.venv/homelink"

    if [[ "$IS_TERMUX" == true ]]; then
        pip install --quiet --upgrade pip setuptools wheel
        pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
        pip install --quiet "$SCRIPT_DIR"
        ok "HomeLink installed (Termux)"
        return
    fi

    # Remove stale venv if Python changed
    if [[ -d "$VENV" ]]; then
        local OLD_PY; OLD_PY=$("$VENV/bin/python" --version 2>/dev/null || echo "none")
        local NEW_PY; NEW_PY=$("$PYTHON" --version 2>/dev/null)
        if [[ "$OLD_PY" != "$NEW_PY" ]]; then
            info "Removing stale venv..."
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
    ok "Entry points ready: $VENV/bin/homelink  $VENV/bin/homectl"
}

# ── PATH setup ────────────────────────────────────────────────────────────────
setup_path() {
    header "Configuring PATH"
    local VENV="${HOME}/.venv/homelink"
    local SHELL_NAME; SHELL_NAME=$(basename "${SHELL:-bash}")

    local RC_FILES=("${HOME}/.bashrc")
    [[ "$SHELL_NAME" == "zsh" ]] && RC_FILES=("${HOME}/.zshrc" "${HOME}/.bashrc")

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
    ok "PATH active for current session"
}

# ── run wizard ────────────────────────────────────────────────────────────────
run_init() {
    header "HomeLink Setup Wizard"
    local VENV="${HOME}/.venv/homelink"
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
    local VENV="${HOME}/.venv/homelink"
    [[ -f "$VENV/bin/homelink" ]] && ok "homelink: $VENV/bin/homelink" || warn "homelink binary not found"
    [[ -f "$VENV/bin/homectl"  ]] && ok "homectl:  $VENV/bin/homectl"
    if command -v homelink &>/dev/null; then
        ok "homelink in PATH ✓"
    else
        warn "homelink not in PATH yet — run: source ~/.bashrc"
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────
banner
detect_env

[[ "$UNINSTALL" == true ]] && { do_uninstall; exit 0; }

install_system_deps
repair_service
install_homelink
[[ "$IS_TERMUX" == false ]] && setup_path
verify_install

echo ""
echo -e "${BOLD}Installation complete!${RESET}"
echo ""

if [[ -t 0 ]]; then
    read -r -p "Run setup wizard now? [Y/n]: " RUN_WIZARD
    [[ "${RUN_WIZARD:-Y}" =~ ^[Yy]?$ ]] && run_init || {
        echo ""
        echo "Run setup later:  bash $SCRIPT_DIR/init.py"
    }
else
    echo "Setup wizard: bash $SCRIPT_DIR/init.py"
    echo "Or:           source ~/.bashrc && homelink --help"
fi
