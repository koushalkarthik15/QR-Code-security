import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:qrshieldpp_mobile/core/config/app_config.dart';
import 'package:qrshieldpp_mobile/data/models/qrshield_models.dart';

class ApiException implements Exception {
  ApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() {
    final codePart = statusCode == null ? '' : ' (HTTP $statusCode)';
    return 'ApiException$codePart: $message';
  }
}

class QRShieldApiClient {
  QRShieldApiClient({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  Future<ScanQrResult> scanQr({
    required String qrContent,
    String qrType = 'auto',
    bool includeExplanation = true,
  }) async {
    if (!AppConfig.isBackendTransportAllowed) {
      throw ApiException(
        'Refusing insecure backend URL. Use HTTPS for non-local hosts.',
      );
    }
    if (AppConfig.apiKey.trim().isEmpty) {
      throw ApiException(
        'QRSHIELD_API_KEY is not configured for this build.',
      );
    }

    final endpoint = AppConfig.endpoint('/scan/qr');
    final payload = <String, dynamic>{
      'qr_content': qrContent,
      'qr_type': qrType,
      'include_explanation': includeExplanation,
    };

    http.Response response;
    try {
      response = await _client.post(
        endpoint,
        headers: <String, String>{
          'Content-Type': 'application/json',
          'X-API-Key': AppConfig.apiKey,
        },
        body: jsonEncode(payload),
      );
    } on SocketException {
      throw ApiException(
        'Cannot reach backend at ${AppConfig.apiBaseUrl}. '
        'Check backend server and network connectivity.',
      );
    }

    final decoded = _decodeJsonMap(response.body);
    final envelope = ApiEnvelope.fromJson(decoded);

    if (response.statusCode >= 400 || !envelope.isSuccess) {
      final errorMessage = envelope.error?.message.isNotEmpty == true
          ? envelope.error!.message
          : 'Backend request failed.';
      throw ApiException(errorMessage, statusCode: response.statusCode);
    }

    return ScanQrResult.fromJson(envelope.data);
  }

  void dispose() {
    _client.close();
  }

  Map<String, dynamic> _decodeJsonMap(String responseBody) {
    try {
      final decoded = jsonDecode(responseBody);
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }
      if (decoded is Map) {
        return decoded.map(
          (key, dynamic value) => MapEntry(key.toString(), value),
        );
      }
      throw const FormatException('Expected JSON object.');
    } on FormatException catch (error) {
      throw ApiException('Invalid backend JSON response: ${error.message}');
    }
  }
}
