# QRShield++ Mobile Screen Flow

1. `QRScannerScreen` (`/`)
- Live camera feed starts with QR-only detection.
- User can also paste manual URL/QR text and tap **Analyze Input**.
- On detection, app sends payload to backend `POST /scan/qr`.

2. `RiskResultScreen` (`/risk-result`)
- Shows final risk score (`0-100`) and threat label (`Safe`, `Suspicious`, `Malicious`).
- Displays backend explanation and top contributing factors.
- User actions:
  - **Proceed (Warning Page)**
  - **Block Link**

3. `WarningGateScreen` (`/warning-gate`)
- Shows warning summary and resolved URL before opening.
- User actions:
  - **Continue Anyway**: opens external browser.
  - **Block and Return**: returns to scanner without opening URL.
