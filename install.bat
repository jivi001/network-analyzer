@echo off
title my-sentinel Installer
echo ================================================
echo  Installing my-sentinel CLI
echo ================================================
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
