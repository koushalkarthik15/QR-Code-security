@echo off
cd /d "%~dp0qrshieldpp-web"
set "QRSHIELD_API_BASE=http://127.0.0.1:8000"
set "QRSHIELD_API_KEY=<YOUR_API_KEY>"
set "QRSHIELD_CLIENT_API_KEY=<YOUR_API_KEY>"
set "NEXT_PUBLIC_QRSHIELD_CLIENT_API_KEY=<YOUR_API_KEY>"
npm run dev > web_run.log 2>&1
