import {
  AnalyzeUrlRequest,
  ApiEnvelope,
  RiskExplainRequest,
  RiskExplanationData,
  RiskFusionData,
  RiskScoreRequest,
  ScanQrData,
  ScanQrRequest
} from "@/types/qrshield";

const CLIENT_API_KEY = process.env.NEXT_PUBLIC_QRSHIELD_CLIENT_API_KEY || "";

async function postJson<TReq, TRes>(path: string, payload: TReq): Promise<ApiEnvelope<TRes>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (CLIENT_API_KEY) {
    headers["X-API-Key"] = CLIENT_API_KEY;
  }

  const response = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(payload)
  });

  const body = await response.json().catch(() => ({
    status: "error",
    error: { message: "Invalid JSON response from backend proxy." }
  }));

  if (!response.ok) {
    const message =
      body?.error?.message ||
      body?.detail ||
      `Backend request failed with status ${response.status}`;
    throw new Error(String(message));
  }

  return body as ApiEnvelope<TRes>;
}

export function analyzeUrl(payload: AnalyzeUrlRequest): Promise<ApiEnvelope<Record<string, unknown>>> {
  return postJson<AnalyzeUrlRequest, Record<string, unknown>>("/api/qrshield/analyze-url", payload);
}

export function scoreRisk(payload: RiskScoreRequest): Promise<ApiEnvelope<RiskFusionData>> {
  return postJson<RiskScoreRequest, RiskFusionData>("/api/qrshield/risk-score", payload);
}

export function explainRisk(payload: RiskExplainRequest): Promise<ApiEnvelope<RiskExplanationData>> {
  return postJson<RiskExplainRequest, RiskExplanationData>("/api/qrshield/risk-explain", payload);
}

export function scanQr(payload: ScanQrRequest): Promise<ApiEnvelope<ScanQrData>> {
  return postJson<ScanQrRequest, ScanQrData>("/api/qrshield/scan", payload);
}
