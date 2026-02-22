@echo off
setlocal

set "SDK_ROOT=C:\Users\Vaishnavi\AppData\Local\Android\Sdk"
set "JAVA_HOME=C:\Progra~1\Android\ANDROI~1\jbr"
set "CMDLINE_ZIP_URL=https://dl.google.com/android/repository/commandlinetools-win-13114758_latest.zip"
set "CMDLINE_ZIP=%TEMP%\commandlinetools-win-latest.zip"
set "EXTRACT_DIR=%TEMP%\cmdline-tools-extract"
set "CMDLINE_TARGET=%SDK_ROOT%\cmdline-tools\latest"
set "SDKMANAGER=%CMDLINE_TARGET%\bin\sdkmanager.bat"

if not exist "%SDK_ROOT%" (
  echo [ERROR] Android SDK root not found: %SDK_ROOT%
  exit /b 1
)

if not exist "%JAVA_HOME%\bin\java.exe" (
  echo [ERROR] Java runtime not found: %JAVA_HOME%\bin\java.exe
  exit /b 1
)

if not exist "%SDKMANAGER%" (
  echo [INFO] Installing Android cmdline-tools...
  if exist "%CMDLINE_ZIP%" del /f /q "%CMDLINE_ZIP%"
  if exist "%EXTRACT_DIR%" rmdir /s /q "%EXTRACT_DIR%"
  mkdir "%EXTRACT_DIR%"

  curl -L --fail --output "%CMDLINE_ZIP%" "%CMDLINE_ZIP_URL%"
  if errorlevel 1 (
    echo [ERROR] Failed to download cmdline-tools.
    exit /b 1
  )

  tar -xf "%CMDLINE_ZIP%" -C "%EXTRACT_DIR%"
  if errorlevel 1 (
    echo [ERROR] Failed to extract cmdline-tools archive.
    exit /b 1
  )

  if not exist "%SDK_ROOT%\cmdline-tools" mkdir "%SDK_ROOT%\cmdline-tools"
  if exist "%CMDLINE_TARGET%" rmdir /s /q "%CMDLINE_TARGET%"

  move "%EXTRACT_DIR%\cmdline-tools" "%CMDLINE_TARGET%" >nul
  if errorlevel 1 (
    echo [ERROR] Failed to place cmdline-tools in SDK.
    exit /b 1
  )
)

set "ANDROID_HOME=%SDK_ROOT%"
set "ANDROID_SDK_ROOT=%SDK_ROOT%"
set "PATH=%JAVA_HOME%\bin;%SDK_ROOT%\platform-tools;%CMDLINE_TARGET%\bin;C:\Windows\System32\WindowsPowerShell\v1.0;%PATH%"

echo [INFO] Installing/updating required Android SDK packages...
call "%SDKMANAGER%" --sdk_root="%SDK_ROOT%" --install "platform-tools" "platforms;android-36" "build-tools;36.1.0"
if errorlevel 1 (
  echo [ERROR] sdkmanager package install failed.
  exit /b 1
)

echo [INFO] Accepting Android SDK licenses...
(for /l %%i in (1,1,80) do @echo y) | call "%SDKMANAGER%" --sdk_root="%SDK_ROOT%" --licenses > "%TEMP%\android-licenses.log"
if errorlevel 1 (
  echo [WARN] License acceptance returned a non-zero exit code. See %TEMP%\android-licenses.log
)

echo [INFO] Connected adb devices:
adb devices

echo [INFO] Flutter doctor (Android section may still show warnings if any optional pieces are missing):
call C:\Users\Vaishnavi\flutter\bin\flutter.bat doctor -v

echo [DONE] Android toolchain setup finished.
exit /b 0
