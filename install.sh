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
    python3 -m venv .venv
fi

# 3. Upgrade pip and build tools
echo "[*] Upgrading pip and build tools..."
.venv/bin/python -m pip install --upgrade pip setuptools wheel --quiet

# 4. Install in editable mode
DEV_FLAG=""
if [ "$1" == "--dev" ]; then
    DEV_FLAG="[dev]"
fi

echo "[*] Installing my-sentinel package in editable mode (.${DEV_FLAG})..."
.venv/bin/python -m pip install -e ".${DEV_FLAG}"

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
echo " Launch locally with:"
echo "   $ ./run.sh             # Interactive TUI"
echo "   $ ./run.sh --capture   # Direct live capture"
echo " Or activate venv:"
echo "   $ source .venv/bin/activate && sentinel"
echo "================================================"
