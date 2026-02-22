class AppConfig {
  // Android emulator can reach host localhost via 10.0.2.2.
  static const String _defaultBaseUrl = String.fromEnvironment(
    'QRSHIELD_API_BASE_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );

  static String get apiBaseUrl => _defaultBaseUrl;
  static const String apiKey = String.fromEnvironment(
    'QRSHIELD_API_KEY',
    defaultValue: '',
  );

  static bool get isBackendTransportAllowed {
    final uri = Uri.tryParse(apiBaseUrl);
    if (uri == null) {
      return false;
    }
    if (uri.scheme == 'https') {
      return true;
    }
    final host = uri.host.toLowerCase();
    return host == '127.0.0.1' || host == 'localhost' || host == '10.0.2.2';
  }

  static Uri endpoint(String path) {
    final normalizedBase = apiBaseUrl.endsWith('/')
        ? apiBaseUrl.substring(0, apiBaseUrl.length - 1)
        : apiBaseUrl;
    final normalizedPath = path.startsWith('/') ? path : '/$path';
    return Uri.parse('$normalizedBase$normalizedPath');
  }
}
