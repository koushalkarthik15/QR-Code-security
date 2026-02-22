export type ThreatLabel = "Safe" | "Suspicious" | "Malicious";

export interface ApiEnvelope<T> {
  status: "success";
  request_id: string;
  timestamp_utc: string;
  data: T;
}

export interface ApiErrorEnvelope {
  status: "error";
  request_id: string;
  timestamp_utc: string;
  error: {
    message: string;
    details?: unknown;
  };
}

export interface AnalyzeUrlRequest {
  url: string;
  include_redirect?: boolean;
  include_temporal?: boolean;
}

export interface ScanQrRequest {
  qr_content: string;
  qr_type: "url" | "text" | "auto";
  image_base64?: string | null;
  include_explanation?: boolean;
}

export interface RiskScoreRequest {
  static_url_risk: number;
  redirect_chain_risk: number;
  image_context_risk: number;
  time_based_risk: number;
}

export interface RiskExplainRequest {
  url: string;
  static_url_risk?: number | null;
  redirect_result?: Record<string, unknown> | null;
  image_result?: Record<string, unknown> | null;
  temporal_result?: Record<string, unknown> | null;
}

export interface RiskFusionData {
  component_risks: Record<string, number>;
  weighted_contributions: Record<string, number>;
  fusion_score_0_1: number;
  final_risk_score_0_100: number;
  threat_label: ThreatLabel;
  errors?: string[];
}

export interface ExplainedFeature {
  feature: string;
  source: string;
  contribution_0_1: number;
  detail: string;
}

export interface RiskExplanationData {
  final_risk_score_0_100: number;
  threat_label: ThreatLabel;
  top_contributors: ExplainedFeature[];
  explanation: string;
  component_risks: Record<string, number>;
  component_weighted_contributions: Record<string, number>;
  errors?: string[];
}

export interface ScanQrData {
  qr_type: "url" | "text" | "auto";
  payload_type?: "http_https" | "upi" | "tel" | "sms" | "other";
  qr_content: string;
  resolved_payload?: string;
  resolved_url: string;
  recommended_action: "allow" | "warn" | "block";
  warning_only?: boolean;
  risk: RiskFusionData;
  analysis: {
    static_url_ml: Record<string, unknown>;
    redirect_chain: Record<string, unknown>;
    image_context: Record<string, unknown>;
    time_based: Record<string, unknown>;
    payload_structural?: Record<string, unknown>;
  };
  explanation?: RiskExplanationData | null;
}
