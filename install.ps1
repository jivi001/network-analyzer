# install.ps1 - Automated Setup & CLI Launcher Installer for my-sentinel
$ErrorActionPreference = "Stop"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host " Installing my-sentinel CLI (Windows Setup) " -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"
$venvScripts = Join-Path $scriptDir ".venv\Scripts"

if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Creating Python virtual environment in .venv..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "[*] Installing my-sentinel package in editable mode..." -ForegroundColor Yellow
& $venvPython -m pip install -e .

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Package installed successfully in editable mode." -ForegroundColor Green
} else {
    Write-Host "[-] Installation failed." -ForegroundColor Red
    exit 1
}

# Add .venv\Scripts to User PATH if not present
Write-Host "[*] Configuring User PATH environment variable..." -ForegroundColor Yellow
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$venvScripts*") {
    $newPath = "$userPath;$venvScripts"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$env:Path;$venvScripts"
    Write-Host "[+] Added '$venvScripts' to User PATH." -ForegroundColor Green
} else {
    Write-Host "[+] '$venvScripts' is already in User PATH." -ForegroundColor Green
}

Write-Host ""
Write-Host "[+] Verification:" -ForegroundColor Cyan
try {
    $cmd = Get-Command sentinel -ErrorAction Stop
    Write-Host "    Command Location: $($cmd.Source)" -ForegroundColor Green
    & sentinel --version
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host " INSTALLATION COMPLETE! " -ForegroundColor Green
    Write-Host " You can now launch sentinel from ANY prompt:" -ForegroundColor Green
    Write-Host "   PS> sentinel" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Green
} catch {
    Write-Host "[!] Note: Please restart your PowerShell window for PATH changes to take effect." -ForegroundColor Yellow
}
