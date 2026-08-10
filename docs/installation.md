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

## 2. Automated Global Installation (Windows)

To install `sentinel` as a global CLI command accessible from any PowerShell prompt:

1. Open PowerShell as Administrator.
2. Navigate to the project directory:
   ```powershell
   cd D:\Programs\Security\network-analyzer
   ```
3. Run the installation script:
   ```powershell
   .\install.ps1
   ```

The script performs:
- Creates a virtual environment in `.venv/`
- Upgrades `pip`, `setuptools`, and `wheel`
- Installs all dependencies from `requirements.txt`
- Installs `my-sentinel` in editable mode (`pip install -e .`)
- Adds `.venv\Scripts` to user `%PATH%`

4. Open a fresh PowerShell window and run:
   ```powershell
   sentinel
   ```

---

## 3. Manual Virtual Environment Installation

### Windows (PowerShell / Command Prompt)

```powershell
# 1. Create virtual environment
python -m venv .venv

# 2. Activate virtual environment
.venv\Scripts\Activate.ps1

# 3. Install requirements
pip install -r requirements.txt

# 4. Install my-sentinel package
pip install -e .

# 5. Launch application
sentinel
```

### Linux / macOS

```bash
# 1. Create virtual environment
python3 -m venv .venv

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Install requirements
pip install -r requirements.txt

# 4. Install package
pip install -e .

# 5. Launch with sudo for raw packet access
sudo .venv/bin/sentinel
```

---

## 4. Dependencies Reference (`requirements.txt`)

```text
scapy>=2.5.0
rich>=13.0.0
python-nmap>=0.7.1
ipwhois>=1.2.0
pyyaml>=6.0
```

---

## 5. Environment Verification Commands

```powershell
# Verify Python version
python --version

# Verify sentinel CLI availability
sentinel --version

# Verify automated test suite execution
python -m pytest tests\ -v
```
