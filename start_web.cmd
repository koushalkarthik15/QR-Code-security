@echo off
cd /d "%~dp0qrshieldpp-web"
set "QRSHIELD_API_BASE=http://127.0.0.1:8000"
set "QRSHIELD_API_KEY=0-MMnmJYNqExEUHDnAIPgtR-GNHqikNK9abHVavoHPY"
set "QRSHIELD_CLIENT_API_KEY=0-MMnmJYNqExEUHDnAIPgtR-GNHqikNK9abHVavoHPY"
set "NEXT_PUBLIC_QRSHIELD_CLIENT_API_KEY=0-MMnmJYNqExEUHDnAIPgtR-GNHqikNK9abHVavoHPY"
npm run dev > web_run.log 2>&1
