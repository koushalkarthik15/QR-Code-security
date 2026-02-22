@echo off
cd /d "%~dp0qrshieldpp-mobile"
set "PATH=C:\Windows\System32\WindowsPowerShell\v1.0;%PATH%"
set "ANDROID_SDK_ROOT=C:\Users\Vaishnavi\AppData\Local\Android\Sdk"
set "ANDROID_HOME=C:\Users\Vaishnavi\AppData\Local\Android\Sdk"
set "ADB_EXE=C:\Users\Vaishnavi\AppData\Local\Android\Sdk\platform-tools\adb.exe"
set "FLUTTER_BAT=C:\Users\Vaishnavi\flutter\bin\flutter.bat"
set "DEVICE_ID=RZCW709LCYF"
set "API_KEY=0-MMnmJYNqExEUHDnAIPgtR-GNHqikNK9abHVavoHPY"

"%ADB_EXE%" devices > "%~dp0qrshieldpp-mobile\adb_devices.log" 2>&1
"%ADB_EXE%" reverse tcp:8000 tcp:8000 >> "%~dp0qrshieldpp-mobile\adb_devices.log" 2>&1
"%ADB_EXE%" reverse --list >> "%~dp0qrshieldpp-mobile\adb_devices.log" 2>&1

"%FLUTTER_BAT%" run -d %DEVICE_ID% --dart-define=QRSHIELD_API_BASE_URL=http://127.0.0.1:8000 --dart-define=QRSHIELD_API_KEY=%API_KEY% > "%~dp0qrshieldpp-mobile\flutter_run.log" 2>&1
