@echo off
cd /d "%~dp0qrshieldpp-backend"
set "QRSHIELD_API_KEY=0-MMnmJYNqExEUHDnAIPgtR-GNHqikNK9abHVavoHPY"
set "QRSHIELD_MAX_IMAGE_BYTES=5242880"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > backend_run.log 2>&1
