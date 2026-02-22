# qrshieldpp_mobile

Flutter client for QRShield++ scanning.

## Run

Pass backend URL and API key as compile-time defines:

```bash
flutter run \
  --dart-define=QRSHIELD_API_BASE_URL=http://10.0.2.2:8000 \
  --dart-define=QRSHIELD_API_KEY=replace-with-client-api-key
```

Notes:
- Use HTTPS for non-local hosts.
- Local emulator defaults (`10.0.2.2`) are allowed for development only.
