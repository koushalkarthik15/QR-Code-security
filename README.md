# QRShield++

QRShield++ is a comprehensive threat detection system for QR codes. It evaluates QR payloads and URLs in real time to prevent phishing, malware distribution, and other malicious activities. The system features a centralized machine learning backend API, a web dashboard, and a mobile application client.

## 🚀 Key Features

*   **Real-time QR Payload Analysis:** Scans and classifies QR code contents (URLs and raw payloads).
*   **Hierarchical Threat Classifier:** Employs machine learning models to classify threats into distinct categories (e.g., Benign, Malware, Phishing).
*   **Payload Preservation Check:** Analyzes structural components of the QR payload to determine safety before deep inspection.
*   **Multi-Client Support:** Includes a mobile application for live scanning and a web dashboard for incident and policy management.

## 🏗️ Architecture & Technologies

The repository is structured into four main components:

1.  **Backend API (`qrshieldpp-backend/`)**
    *   **Framework:** Python, FastAPI, Uvicorn
    *   **Core Libraries:** scikit-learn, LightGBM, OpenCV, Pandas, NumPy
    *   **Functionality:** Exposes REST API endpoints for QR scanning and hosts the ML inference engine.
2.  **Machine Learning Pipeline (`qrshieldpp-ml/`)**
    *   **Tech Stack:** Python, scikit-learn, LightGBM, pandas, pyarrow, joblib
    *   **Functionality:** Contains code for model training, feature extraction, calibration, and experiments.
3.  **Web Application (`qrshieldpp-web/`)**
    *   **Framework:** Next.js (React 18), TypeScript
    *   **Core Libraries:** JSQR for QR processing
    *   **Functionality:** A dashboard application with pages for incidents, policies, settings, and warnings.
4.  **Mobile Application (`qrshieldpp-mobile/`)**
    *   **Framework:** Flutter, Dart
    *   **Core Libraries:** `mobile_scanner`, `http`, `url_launcher`
    *   **Functionality:** Android application for live scanning of QR codes and immediate risk assessment.

## 📂 Project Structure

```text
qrshield/
├── qrshieldpp-backend/    # FastAPI server and ML inference service
│   ├── app/               # Main application code (api, core, domain, services)
│   ├── Dockerfile         # Docker configuration for backend
│   └── vercel.json        # Vercel deployment configuration
├── qrshieldpp-ml/         # Machine learning pipeline, training, and models
│   └── src/qrshield_ml/   # ML source code (features, models, evaluation)
├── qrshieldpp-mobile/     # Flutter mobile application
│   └── lib/               # Dart source code (features, services, data)
├── qrshieldpp-web/        # Next.js web dashboard
│   └── src/app/           # Next.js App Router pages (dashboard, incidents, etc.)
└── start_*.cmd            # Windows batch scripts for local development
```

## 🔌 API Endpoints

The backend exposes several endpoints. The primary scanning route is in the `v2` API:

*   `GET /`: Returns service status and available endpoint list.
*   `GET /health`: Health probe (`{"status": "ok"}`).
*   `GET /ready`: Readiness probe verifying that the ML models are fully loaded.
*   `POST /api/v2/qr`: The main scanning endpoint.
    *   **Request Body:** `{"raw_payload": "string", "url_candidate": "string"}`
    *   **Response:** Returns a `ScanResponseV2` object containing the classification (`SAFE`, `MALWARE_DETECTED`, `PHISHING_DETECTED`, `SCAN_ERROR`) and recommended action (`allow`, `block`).

## ⚙️ Environment Variables

### Backend (`qrshieldpp-backend`)
*   `QRSHIELD_API_KEY`: Authentication key for API access.
*   `QRSHIELD_MAX_IMAGE_BYTES`: Maximum allowed size for image payloads (e.g., `5242880`).

### Web (`qrshieldpp-web`)
*   `QRSHIELD_API_BASE`: URL of the backend API (e.g., `http://127.0.0.1:8000`).
*   `QRSHIELD_API_KEY`: Server-side API key.
*   `QRSHIELD_CLIENT_API_KEY` / `NEXT_PUBLIC_QRSHIELD_CLIENT_API_KEY`: Client-facing API key for browser requests.

### Mobile (`qrshieldpp-mobile`)
Passed via `--dart-define` during compilation:
*   `QRSHIELD_API_BASE_URL`: URL of the backend API.
*   `QRSHIELD_API_KEY`: Authentication key for API access.

## 💻 Local Development & Setup

Windows `.cmd` scripts are provided in the repository root to start the various services locally.

1.  **Start the Backend:**
    Run `start_backend.cmd`. This will navigate to the backend directory, set environment variables, and run the FastAPI server via Uvicorn on `127.0.0.1:8000`. Output is logged to `backend_run.log`.

2.  **Start the Web Dashboard:**
    Run `start_web.cmd`. This starts the Next.js development server. Output is logged to `web_run.log`.

3.  **Start the Mobile App (USB Debugging):**
    Run `start_mobile_usb.cmd`. This script configures ADB reverse port forwarding (so the device can reach `localhost:8000`) and launches the Flutter application on a connected Android device. Output is logged to `flutter_run.log`.

