@echo off
:: USB Triage — Windows launcher
:: Auto-elevates to Administrator (required for full output)

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

powershell -ExecutionPolicy Bypass -File "%~dp0windows-audit.ps1" %*
pause
