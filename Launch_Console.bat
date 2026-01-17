@echo off
cd /d "%~dp0"
title Portable Web Tool
echo Starting Portable PowerShell 7...
".\pwsh\pwsh.exe" -NoExit -ExecutionPolicy Bypass -Command "Import-Module .\Get-WebPage.ps1; Write-Host 'Portable Environment Ready!' -ForegroundColor Green; Write-Host 'Type Get-WebPage to start.' -ForegroundColor Yellow"
