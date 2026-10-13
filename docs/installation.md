# Installation & Setup Guide

## 1. Environment Requirements

| Requirement | Supported Version / Requirement | Notes |
|-------------|---------------------------------|-------|
| **Operating System** | Windows 10/11, Windows Server, Linux (Ubuntu/Debian) | Native Windows support via PowerShell scripts & `.venv`. |
| **Python** | Python 3.10, 3.11, 3.12, 3.13 | Standard Python installation with `pip` and `venv`. |
| **Packet Capture Driver** | Npcap (Windows) or libpcap (Linux) | **Required for raw socket capture.** Windows requires Npcap installed in WinPcap API-compatible mode. |
| **Network Scanner** | Nmap 7.90+ | **Required for network scanning.** Nmap binary must be in system `%PATH%`. |
| **Privileges** | Administrator / root | Required for opening raw packet capture sockets and SYN/OS scanning. |

---

## 2. Automated Cross-Platform Installation

### Linux / macOS / WSL

To install `sentinel` as a CLI command accessible across your environment:

1. Open your terminal and navigate to the project directory:
   ```bash
   cd network-analyzer
   ```
2. Make the installer executable and run it:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```
   *(Optional: pass `--dev` to include development and test dependencies: `./install.sh --dev`)*

The script automatically:
- Detects `uv` (fast installer) or standard `python3`.
- Creates `.venv/` virtual environment.
- Bootstraps `pip` / `uv` without failing if `pip` is omitted in the base environment.
- Installs `my-sentinel` in editable mode (`-e .`).
- Sets execution permissions on `./run.sh`.
- Creates a user launcher symlink in `~/.local/bin/sentinel` for immediate command-line access.
- Checks Linux network capabilities (`cap_net_raw,cap_net_admin`) and Nmap presence.

3. Run `sentinel` directly:
   ```bash
   sentinel
   ```

---

### Windows (PowerShell / Command Prompt)

To install `sentinel` as a global CLI command accessible from any PowerShell prompt:

1. Open PowerShell as Administrator.
2. Navigate to the project directory:
   ```powershell
   cd network-analyzer
   ```
3. Run the installation script (or execute `install.bat`):
   ```powershell
   .\install.ps1
   ```
   *(Optional: pass `-Dev` to include test dependencies: `.\install.ps1 -Dev`)*

The script automatically:
- Terminates any running locked sentinel processes.
- Detects `uv` or `python` and initializes `.venv\`.
- Bootstraps `pip` via `ensurepip` if missing.
- Installs `my-sentinel` in editable mode.
- Appends `.venv\Scripts` to User and Machine `%PATH%`.
- Validates Npcap packet capture driver and Nmap binary installation.

4. Open a fresh PowerShell window and run:
   ```powershell
   sentinel
   ```

---

## 3. Manual Virtual Environment Installation

### Option A: Ultra-Fast Installation with `uv` (Cross-Platform)

```bash
# 1. Create virtual environment
uv venv .venv

# 2. Sync all dependencies and install in editable mode
uv pip install -e ".[dev]"

# 3. Launch
uv run sentinel
```

### Option B: Standard Python (`venv` & `pip`)

#### Windows (PowerShell)
```powershell
# 1. Create virtual environment
python -m venv .venv

# 2. Activate virtual environment
.venv\Scripts\Activate.ps1

# 3. Upgrade build tools
python -m pip install --upgrade pip setuptools wheel

# 4. Install my-sentinel package
pip install -e .

# 5. Launch application
sentinel
```

#### Linux / macOS
```bash
# 1. Create virtual environment
python3 -m venv .venv

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Upgrade build tools
python3 -m pip install --upgrade pip setuptools wheel

# 4. Install package
pip install -e .

# 5. Launch with sudo for raw packet capture
sudo .venv/bin/sentinel
```

---

## 4. Dependencies Reference (`pyproject.toml` / `requirements.txt`)

```text
scapy>=2.5.0
rich>=13.0.0
python-nmap>=0.7.1
ipwhois>=1.2.0
pyyaml>=6.0
```

---

## 5. Environment Verification Commands

```bash
# Verify Python version
python3 --version  # or python --version

# Verify sentinel CLI availability
sentinel --version

# Verify automated test suite execution (286 tests, 100% pass)
uv run --extra dev pytest tests/ -v
# Or via standard pytest
pytest tests/ -v
```
