class TopContributor {
  TopContributor({
    required this.feature,
    required this.source,
    required this.contribution01,
    required this.detail,
  });

  final String feature;
  final String source;
  final double contribution01;
  final String detail;

  factory TopContributor.fromJson(Map<String, dynamic> json) {
    return TopContributor(
      feature: _readString(json['feature']),
      source: _readString(json['source']),
      contribution01: _readDouble(json['contribution_0_1']),
      detail: _readString(json['detail']),
    );
  }
}

class DecisionExplanation {
  DecisionExplanation({
    required this.finalRiskScore0100,
    required this.threatLabel,
    required this.explanation,
    required this.topContributors,
    required this.raw,
  });

  final double finalRiskScore0100;
  final String threatLabel;
  final String explanation;
  final List<TopContributor> topContributors;
  final Map<String, dynamic> raw;

  factory DecisionExplanation.fromJson(Map<String, dynamic> json) {
    final contributors = _readList(
      json['top_contributors'],
      (item) => TopContributor.fromJson(_readMap(item)),
    );

    return DecisionExplanation(
      finalRiskScore0100: _readDouble(json['final_risk_score_0_100']),
      threatLabel: _readString(json['threat_label']),
      explanation: _readString(json['explanation']),
      topContributors: contributors,
      raw: json,
    );
  }
}

class FusedRisk {
  FusedRisk({
    required this.fusionScore01,
    required this.finalRiskScore0100,
    required this.threatLabel,
    required this.componentRisks,
    required this.weightedContributions,
    required this.errors,
    required this.raw,
  });

  final double fusionScore01;
  final double finalRiskScore0100;
  final String threatLabel;
  final Map<String, double> componentRisks;
  final Map<String, double> weightedContributions;
  final List<String> errors;
  final Map<String, dynamic> raw;

  factory FusedRisk.fromJson(Map<String, dynamic> json) {
    return FusedRisk(
      fusionScore01: _readDouble(json['fusion_score_0_1']),
      finalRiskScore0100: _readDouble(json['final_risk_score_0_100']),
      threatLabel: _readString(json['threat_label']),
      componentRisks: _readDoubleMap(json['component_risks']),
      weightedContributions: _readDoubleMap(json['weighted_contributions']),
      errors: _readList(json['errors'], (item) => item.toString()),
      raw: json,
    );
  }
}

class ScanQrResult {
  ScanQrResult({
    required this.qrType,
    required this.payloadType,
    required this.qrContent,
    required this.resolvedPayload,
    required this.resolvedUrl,
    required this.warningOnly,
    required this.recommendedAction,
    required this.risk,
    required this.analysis,
    required this.explanation,
    required this.raw,
  });

  final String qrType;
  final String payloadType;
  final String qrContent;
  final String resolvedPayload;
  final String resolvedUrl;
  final bool warningOnly;
  final String recommendedAction;
  final FusedRisk risk;
  final Map<String, dynamic> analysis;
  final DecisionExplanation? explanation;
  final Map<String, dynamic> raw;

  factory ScanQrResult.fromJson(Map<String, dynamic> json) {
    final explanationJson = json['explanation'];
    final maybeExplanationMap = _readNullableMap(explanationJson);

    return ScanQrResult(
      qrType: _readString(json['qr_type']),
      payloadType: _readString(
        json['payload_type'],
        fallback: _readString(json['qr_type'], fallback: 'other'),
      ),
      qrContent: _readString(json['qr_content']),
      resolvedPayload: _readString(
        json['resolved_payload'],
        fallback: _readString(
          json['resolved_url'],
          fallback: _readString(json['qr_content']),
        ),
      ),
      resolvedUrl: _readString(
        json['resolved_url'],
        fallback: _readString(json['resolved_payload']),
      ),
      warningOnly: _readBool(json['warning_only']),
      recommendedAction: _readString(json['recommended_action']),
      risk: FusedRisk.fromJson(_readMap(json['risk'])),
      analysis: _readMap(json['analysis']),
      explanation: maybeExplanationMap == null
          ? null
          : DecisionExplanation.fromJson(maybeExplanationMap),
      raw: json,
    );
  }
}

class ApiErrorDetail {
  ApiErrorDetail({
    required this.message,
    required this.details,
  });

  final String message;
  final dynamic details;

  factory ApiErrorDetail.fromJson(Map<String, dynamic> json) {
    return ApiErrorDetail(
      message: _readString(json['message']),
      details: json['details'],
    );
  }
}

class ApiEnvelope {
  ApiEnvelope({
    required this.status,
    required this.requestId,
    required this.timestampUtc,
    required this.data,
    required this.error,
    required this.raw,
  });

  final String status;
  final String requestId;
  final String timestampUtc;
  final Map<String, dynamic> data;
  final ApiErrorDetail? error;
  final Map<String, dynamic> raw;

  bool get isSuccess => status == 'success';

  factory ApiEnvelope.fromJson(Map<String, dynamic> json) {
    final errorMap = _readNullableMap(json['error']);
    return ApiEnvelope(
      status: _readString(json['status']),
      requestId: _readString(json['request_id']),
      timestampUtc: _readString(json['timestamp_utc']),
      data: _readMap(json['data']),
      error: errorMap == null ? null : ApiErrorDetail.fromJson(errorMap),
      raw: json,
    );
  }
}

double _readDouble(dynamic value, {double fallback = 0.0}) {
  if (value is num) {
    return value.toDouble();
  }
  if (value is String) {
    return double.tryParse(value) ?? fallback;
  }
  return fallback;
}

String _readString(dynamic value, {String fallback = ''}) {
  if (value == null) {
    return fallback;
  }
  return value.toString();
}

Map<String, dynamic> _readMap(dynamic value) {
  if (value is Map<String, dynamic>) {
    return value;
  }
  if (value is Map) {
    return value.map(
      (key, dynamic mapValue) => MapEntry(key.toString(), mapValue),
    );
  }
  return <String, dynamic>{};
}

Map<String, dynamic>? _readNullableMap(dynamic value) {
  if (value == null) {
    return null;
  }
  final map = _readMap(value);
  if (map.isEmpty) {
    return null;
  }
  return map;
}

Map<String, double> _readDoubleMap(dynamic value) {
  final map = _readMap(value);
  final output = <String, double>{};
  for (final entry in map.entries) {
    output[entry.key] = _readDouble(entry.value);
  }
  return output;
}

List<T> _readList<T>(dynamic value, T Function(dynamic item) mapper) {
  if (value is! List) {
    return <T>[];
  }
  return value.map(mapper).toList();
}

bool _readBool(dynamic value, {bool fallback = false}) {
  if (value is bool) {
    return value;
  }
  if (value is num) {
    return value != 0;
  }
  if (value is String) {
    final normalized = value.trim().toLowerCase();
    if (normalized == 'true' || normalized == '1' || normalized == 'yes') {
      return true;
    }
    if (normalized == 'false' || normalized == '0' || normalized == 'no') {
      return false;
    }
  }
  return fallback;
}
