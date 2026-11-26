@echo off
setlocal
cd /d "%~dp0"

echo.
echo ================================================
echo        Installing my-sentinel CLI
echo ================================================

rem 0. Terminate any running sentinel processes that may lock .venv files
tasklist /FI "IMAGENAME eq sentinel.exe" 2>nul | find /I "sentinel.exe" >nul
if not errorlevel 1 (
    echo [!] Found running sentinel process(es). Terminating to prevent file locking...
    taskkill /IM sentinel.exe /F /T >nul 2>&1
    taskkill /IM sentinal.exe /F /T >nul 2>&1
    timeout /t 1 /nobreak >nul
)

rem Pre-clean existing entrypoint binaries before reinstall
if exist ".venv\Scripts\sentinel.exe" del /f /q ".venv\Scripts\sentinel.exe" >nul 2>&1
if exist ".venv\Scripts\sentinal.exe" del /f /q ".venv\Scripts\sentinal.exe" >nul 2>&1

rem Clean up any stale pip temporary directories
if exist ".venv\Lib\site-packages\~*" (
    echo [*] Cleaning up temporary pip artifacts...
    for /d %%d in (".venv\Lib\site-packages\~*") do rd /s /q "%%d" >nul 2>&1
)

rem Delegate to PowerShell installer for full setup
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*