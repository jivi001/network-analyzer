# run.ps1 - Direct launcher for my-sentinel
[CmdletBinding()]
param (
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SentinelArgs
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Virtual environment not found. Running installer first..." -ForegroundColor Yellow
    & (Join-Path $scriptDir "install.ps1")
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

& $venvPython (Join-Path $scriptDir "sentinel.py") @SentinelArgs
