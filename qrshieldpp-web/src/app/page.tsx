"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";

import RiskScoreDisplay from "@/components/risk-score-display";
import ThreatExplanationPanel from "@/components/threat-explanation-panel";
import { scanQr } from "@/lib/api-client/qrshield";
import { ScanQrData } from "@/types/qrshield";

type ScanState = {
  loading: boolean;
  error: string | null;
  result: ScanQrData | null;
};

function normalizeUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) {
    return "";
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.toString();
  } catch {
    return "";
  }
}

async function fileToDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("Failed to read image file."));
    reader.readAsDataURL(file);
  });
}

async function detectQrTextFromFile(file: File): Promise<string | null> {
  if (typeof window === "undefined") {
    return null;
  }

  const DetectorCtor = (window as Window & { BarcodeDetector?: any }).BarcodeDetector;
  if (!DetectorCtor) {
    return null;
  }

  const detector = new DetectorCtor({ formats: ["qr_code"] });
  const bitmap = await createImageBitmap(file);
  try {
    const detections = await detector.detect(bitmap);
    const first = detections?.[0];
    const rawValue = first?.rawValue;
    return rawValue ? String(rawValue) : null;
  } finally {
    if (typeof bitmap.close === "function") {
      bitmap.close();
    }
  }
}

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [decodedQrText, setDecodedQrText] = useState<string>("");
  const [manualUrl, setManualUrl] = useState<string>("");
  const [decodeMessage, setDecodeMessage] = useState<string>("");
  const [scan, setScan] = useState<ScanState>({ loading: false, error: null, result: null });

  useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  const resolvedInputUrl = useMemo(() => {
    const candidate = manualUrl.trim() || decodedQrText.trim();
    return candidate;
  }, [decodedQrText, manualUrl]);

  async function onSelectFile(selected: File | null) {
    setFile(selected);
    setScan({ loading: false, error: null, result: null });

    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }

    if (!selected) {
      setDecodedQrText("");
      setDecodeMessage("");
      return;
    }

    if (!selected.type.startsWith("image/")) {
      setDecodeMessage("Please select a valid image file.");
      setDecodedQrText("");
      return;
    }

    const objectUrl = URL.createObjectURL(selected);
    setPreviewUrl(objectUrl);
    setDecodeMessage("Trying to decode QR text from the image...");

    try {
      const detected = await detectQrTextFromFile(selected);
      if (detected) {
        setDecodedQrText(detected);
        setDecodeMessage("QR text detected from image.");
      } else {
        setDecodedQrText("");
        setDecodeMessage("Auto decode unavailable/failed. Enter URL manually below.");
      }
    } catch (error) {
      setDecodedQrText("");
      setDecodeMessage(`QR decode failed: ${String(error)}`);
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setScan({ loading: true, error: null, result: null });

    const qrContent = resolvedInputUrl;
    if (!qrContent) {
      setScan({
        loading: false,
        error: "Provide a URL manually or upload a QR image that can be decoded.",
        result: null
      });
      return;
    }

    try {
      const imageBase64 = file ? await fileToDataUrl(file) : null;
      const response = await scanQr({
        qr_content: qrContent,
        qr_type: "auto",
        image_base64: imageBase64,
        include_explanation: true
      });
      setScan({ loading: false, error: null, result: response.data });
    } catch (error) {
      setScan({
        loading: false,
        error: error instanceof Error ? error.message : "Scan failed.",
        result: null
      });
    }
  }

  const warningHref = useMemo(() => {
    if (!scan.result) {
      return null;
    }
    if (scan.result.payload_type && scan.result.payload_type !== "http_https") {
      return null;
    }

    const payload = scan.result.resolved_payload || scan.result.resolved_url;
    if (!payload) {
      return null;
    }

    const normalizedUrl = normalizeUrl(payload);
    if (!normalizedUrl) {
      return null;
    }

    const params = new URLSearchParams({
      url: normalizedUrl,
      score: String(scan.result.risk.final_risk_score_0_100),
      label: scan.result.risk.threat_label,
      reason: scan.result.explanation?.explanation || ""
    });
    return `/warning?${params.toString()}`;
  }, [scan.result]);

  const redirectScore = Number(scan.result?.analysis?.redirect_chain?.risk_score ?? 0);
  const imageScore = Number(scan.result?.analysis?.image_context?.risk_score ?? 0);
  const timeScore = Number(scan.result?.analysis?.time_based?.risk_score ?? 0);

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">QRShield++</p>
        <h1>QR Risk Scanner</h1>
        <p className="muted">
          Upload a QR image, run integrated backend analysis, inspect risk score, and review the
          explanation before opening any decoded payload.
        </p>
      </section>

      <section className="panel">
        <h2>1) Upload QR Image</h2>
        <form onSubmit={onSubmit} className="form-grid">
          <label className="field">
            QR Image
            <input
              type="file"
              accept="image/*"
              onChange={(event) => onSelectFile(event.target.files?.[0] || null)}
            />
          </label>

          <label className="field">
            URL (manual fallback)
            <input
              type="text"
              value={manualUrl}
              placeholder="https://example.com"
              onChange={(event) => setManualUrl(event.target.value)}
            />
          </label>

          <p className="muted">{decodeMessage}</p>
          {decodedQrText ? (
            <p className="detected-text">
              Detected QR text: <code>{decodedQrText}</code>
            </p>
          ) : null}
          {previewUrl ? <img src={previewUrl} alt="Uploaded QR preview" className="preview" /> : null}

          <button type="submit" className="btn-primary" disabled={scan.loading}>
            {scan.loading ? "Analyzing..." : "Analyze QR"}
          </button>
        </form>
      </section>

      {scan.error ? <p className="error">{scan.error}</p> : null}

      {scan.result ? (
        <>
          <RiskScoreDisplay
            score={scan.result.risk.final_risk_score_0_100}
            label={scan.result.risk.threat_label}
          />

          <section className="panel">
            <h2>Module Risk Breakdown</h2>
            <p className="muted">Payload Type: {scan.result.payload_type || "http_https"}</p>
            <div className="breakdown-grid">
              <div>
                <p className="muted">Static URL ML</p>
                <strong>{(scan.result.risk.component_risks.static_url_ml * 100).toFixed(2)}%</strong>
              </div>
              <div>
                <p className="muted">Redirect Chain</p>
                <strong>{(redirectScore * 100).toFixed(2)}%</strong>
              </div>
              <div>
                <p className="muted">Image Context</p>
                <strong>{(imageScore * 100).toFixed(2)}%</strong>
              </div>
              <div>
                <p className="muted">Time Based</p>
                <strong>{(timeScore * 100).toFixed(2)}%</strong>
              </div>
            </div>
          </section>

          <ThreatExplanationPanel explanation={scan.result.explanation} />

          <section className="panel">
            <h2>Open Payload</h2>
            <p>
              Target Payload: <code>{scan.result.resolved_payload || scan.result.resolved_url}</code>
            </p>
            <p className="muted">
              A warning gate is shown before navigation so users can review risk details.
            </p>
            {warningHref ? (
              <Link href={warningHref} className="btn-primary">
                Continue to Warning Page
              </Link>
            ) : (
              <span className="muted">
                Non-web payload detected. Review warnings, then open it in a compatible app.
              </span>
            )}
          </section>
        </>
      ) : null}
    </main>
  );
}
