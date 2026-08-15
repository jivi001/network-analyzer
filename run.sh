#!/usr/bin/env bash
# run.sh - Direct launcher for Linux/macOS/WSL
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f ".venv/bin/python" ]; then
    echo "[*] Virtual environment not found. Running installer first..."
    ./install.sh
fi

exec .venv/bin/python sentinel.py "$@"
