#!/usr/bin/env bash
# install.sh - Automated Setup & CLI Launcher Installer for Linux/macOS/WSL
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================"
echo "       🛡️  Installing my-sentinel CLI 🛡️       "
echo "================================================"

# 1. Check Python
if ! command -v python3 &>/dev/null; then
    echo "[-] python3 is not installed. Please install Python 3.9+."
    exit 1
fi

# 2. Virtual Environment
if [ ! -f ".venv/bin/python" ]; then
    echo "[*] Creating Python virtual environment in .venv..."
    if command -v uv &>/dev/null; then
        uv venv .venv
    else
        python3 -m venv .venv
    fi
fi

# Ensure run.sh is executable
chmod +x run.sh 2>/dev/null || true

# 3. Ensure pip or uv is available
DEV_FLAG=""
if [ "$1" == "--dev" ]; then
    DEV_FLAG="[dev]"
fi

if command -v uv &>/dev/null; then
    echo "[*] Installing my-sentinel package via uv..."
    uv pip install -e ".${DEV_FLAG}"
else
    if ! .venv/bin/python -m pip --version &>/dev/null; then
        echo "[*] Bootstrapping pip into virtual environment..."
        .venv/bin/python -m ensurepip --default-pip --upgrade 2>/dev/null || true
    fi

    echo "[*] Upgrading pip and build tools..."
    .venv/bin/python -m pip install --upgrade pip setuptools wheel --quiet 2>/dev/null || true

    echo "[*] Installing my-sentinel package in editable mode (.${DEV_FLAG})..."
    .venv/bin/python -m pip install -e ".${DEV_FLAG}"
fi

# 4. User CLI Launcher in ~/.local/bin
if [ -f ".venv/bin/sentinel" ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$SCRIPT_DIR/.venv/bin/sentinel" "$HOME/.local/bin/sentinel"
    echo "[*] Created user launcher: ~/.local/bin/sentinel"
fi

# 5. System diagnostics
echo ""
echo "[*] System Diagnostics & Prerequisites:"
if [ "$(id -u)" -eq 0 ]; then
    echo "    [✓] Running as root (Full packet sniffing available)"
else
    echo "    [!] Running as unprivileged user: packet sniffing may require 'sudo setcap cap_net_raw,cap_net_admin=eip \$(readlink -f .venv/bin/python)'"
fi

if command -v nmap &>/dev/null; then
    echo "    [✓] Nmap Scanner: Installed ($(nmap --version | head -n 1))"
else
    echo "    [!] Nmap Scanner: Optional — Install via 'sudo apt install nmap' or 'brew install nmap'"
fi

echo ""
echo "================================================"
echo "          INSTALLATION COMPLETE!                "
echo " Launch directly from terminal:"
echo "   $ sentinel"
echo ""
echo " Or launch locally with:"
echo "   $ ./run.sh             # Interactive TUI"
echo "   $ ./run.sh --capture   # Direct live capture"
echo " Or activate venv:"
echo "   $ source .venv/bin/activate && sentinel"
echo "================================================"
