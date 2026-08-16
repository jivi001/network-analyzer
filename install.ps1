# install.ps1 - Automated Setup & CLI Launcher Installer for my-sentinel
[CmdletBinding()]
param (
    [switch]$Dev,
    [switch]$SkipPrereqCheck
)

$ErrorActionPreference = "Stop"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "           Installing my-sentinel CLI           " -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

# 1. Check Python Availability and Version
Write-Host "[*] Checking Python environment..." -ForegroundColor Yellow
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Python is not found in PATH. Please install Python 3.9+ from https://python.org." -ForegroundColor Red
    exit 1
}
$pythonVersionOutput = & python --version 2>&1
Write-Host "    Found: $pythonVersionOutput" -ForegroundColor Gray

# 2. Terminate any running sentinel instances that may lock .venv files
$runningSentinel = Get-Process -Name sentinel, sentinal -ErrorAction SilentlyContinue
if ($runningSentinel) {
    Write-Host "[!] Found running sentinel process(es). Terminating to prevent file locking..." -ForegroundColor Yellow
    $runningSentinel | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

# 3. Clean up any stale pip temporary directories
$staleDirs = Get-ChildItem -Path "$scriptDir\.venv\Lib\site-packages" -Filter "~*" -ErrorAction SilentlyContinue
if ($staleDirs) {
    Write-Host "[*] Cleaning up temporary pip artifacts..." -ForegroundColor Gray
    $staleDirs | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. Virtual Environment Setup
$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"
$venvScripts = Join-Path $scriptDir ".venv\Scripts"

if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Creating Python virtual environment in .venv..." -ForegroundColor Yellow
    & python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Failed to create virtual environment." -ForegroundColor Red
        exit 1
    }
}

# 5. Pre-clean and unlock existing entrypoint binaries
if (Test-Path $venvScripts) {
    foreach ($binName in @("sentinel.exe", "sentinal.exe")) {
        $binPath = Join-Path $venvScripts $binName
        if (Test-Path $binPath) {
            try {
                Remove-Item -Force $binPath -ErrorAction Stop
            }
            catch {
                $oldName = "$binName.old.$PID"
                try {
                    Rename-Item -Path $binPath -NewName $oldName -Force -ErrorAction SilentlyContinue
                } catch {}
            }
        }
    }
}

# 6. Upgrade Pip and Build Tools
Write-Host "[*] Upgrading pip, setuptools, and wheel..." -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip setuptools wheel --quiet

# 7. Install Package in Editable Mode
$installTarget = if ($Dev) { ".[dev]" } else { "." }
Write-Host "[*] Installing my-sentinel package in editable mode ($installTarget)..." -ForegroundColor Yellow
& $venvPython -m pip install -e $installTarget

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Installation failed. Check the error output above." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Package installed successfully in editable mode." -ForegroundColor Green

# 8. Configure Environment PATH
Write-Host "[*] Configuring PATH environment variables..." -ForegroundColor Yellow
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$venvScripts*") {
    $newPath = if ($userPath) { "$userPath;$venvScripts" } else { $venvScripts }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "[+] Added '$venvScripts' to User PATH." -ForegroundColor Green
}
else {
    Write-Host "[+] '$venvScripts' is already in User PATH." -ForegroundColor Green
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$venvScripts*") {
        $newMachinePath = if ($machinePath) { "$machinePath;$venvScripts" } else { $venvScripts }
        [Environment]::SetEnvironmentVariable("Path", $newMachinePath, "Machine")
        Write-Host "[+] Added '$venvScripts' to System (Machine) PATH." -ForegroundColor Green
    }
}

# Refresh session PATH
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")

# 9. Check Prerequisites Diagnostics
if (-not $SkipPrereqCheck) {
    Write-Host ""
    Write-Host "[*] System Diagnostics & Prerequisites:" -ForegroundColor Cyan
    
    # Check Admin
    if ($isAdmin) {
        Write-Host "    [✓] Administrator Privileges: Elevated (Full packet sniffing available)" -ForegroundColor Green
    }
    else {
        Write-Host "    [!] Administrator Privileges: Standard user (Run as Admin for live packet sniffing)" -ForegroundColor Yellow
    }

    # Check Npcap / WinPcap
    $npcapDll = "$env:SystemRoot\System32\Npcap\wpcap.dll"
    $winpcapDll = "$env:SystemRoot\System32\wpcap.dll"
    if ((Test-Path $npcapDll) -or (Test-Path $winpcapDll)) {
        Write-Host "    [✓] Packet Capture Driver: Installed (Npcap/WinPcap detected)" -ForegroundColor Green
    }
    else {
        Write-Host "    [!] Packet Capture Driver: Not found! Install Npcap (https://npcap.com) for live sniffing." -ForegroundColor Yellow
    }

    # Check Nmap
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        $nmapRaw = & nmap --version 2>&1
        $nmapFirst = if ($nmapRaw) { ($nmapRaw | Select-Object -First 1).ToString().Trim() } else { "detected" }
        Write-Host "    [✓] Nmap Scanner: Installed ($nmapFirst)" -ForegroundColor Green
    }
    else {
        Write-Host "    [!] Nmap Scanner: Optional — Install Nmap (https://nmap.org) for active scanning." -ForegroundColor Yellow
    }
}

# 10. Verification
Write-Host ""
Write-Host "[+] Verifying CLI Executables:" -ForegroundColor Cyan
if (Get-Command sentinel -ErrorAction SilentlyContinue) {
    $cmdSentinel = Get-Command sentinel
    Write-Host "    'sentinel' -> $($cmdSentinel.Source)" -ForegroundColor Green
    & sentinel --version
}
else {
    Write-Host "    Direct call via venv: $venvPython sentinel.py --version" -ForegroundColor Gray
    & $venvPython (Join-Path $scriptDir "sentinel.py") --version
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "          INSTALLATION COMPLETE!                " -ForegroundColor Green
Write-Host " Launch from any terminal:" -ForegroundColor Green
Write-Host "   PS> sentinel           # Interactive TUI" -ForegroundColor White
Write-Host "   PS> sentinel --capture # Direct live capture" -ForegroundColor White
Write-Host "   PS> sentinel --help    # Show CLI arguments" -ForegroundColor White
Write-Host " Or run locally via:" -ForegroundColor Green
Write-Host "   PS> .\run.bat          # Instant launcher" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Green
