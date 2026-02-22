"""Service container and orchestration for QRShield++ backend endpoints."""

from __future__ import annotations

import base64
import os
import re
import socket
import tempfile
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException

from app.core.settings import get_settings
from app.detection.layers.decision_explainer import QRShieldDecisionExplainer
from app.detection.layers.image_context_analyzer import QRImageContextAnalyzer
from app.detection.layers.qr_payload_analyzer import QRPayloadAnalysisResult, QRPayloadAnalyzer
from app.detection.layers.redirect_chain_analyzer import RedirectChainAnalyzer
from app.detection.layers.risk_fusion_engine import RiskFusionEngine, RiskFusionInput
from app.detection.layers.temporal_url_risk import TemporalURLRiskModel
from app.ml.inference.static_url_inference import StaticURLModelInference


URL_PATTERN = re.compile(
    r"(?i)\b((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?)"
)
ALLOWED_URL_SCHEMES = {"http", "https"}
DISALLOWED_HOSTS = {"localhost", "localhost.localdomain"}


class QRShieldService:
    """Orchestrates all QRShield++ analysis modules."""

    def __init__(self, static_model_path: Path, max_image_bytes: int) -> None:
        self.static_model_path = static_model_path
        self.max_image_bytes = int(max(256 * 1024, max_image_bytes))
        self.static_inference: StaticURLModelInference | None = None
        self.static_model_error: str | None = None

        if static_model_path.exists():
            self.static_inference = StaticURLModelInference(static_model_path)
            self.decision_explainer = QRShieldDecisionExplainer(
                static_url_model_path=str(static_model_path)
            )
        else:
            self.static_model_error = (
                f"Static URL model not found at {static_model_path}. "
                "URL risk falls back to 0.0 unless provided by request."
            )
            self.decision_explainer = QRShieldDecisionExplainer(static_url_model=None)

        self.redirect_analyzer = RedirectChainAnalyzer()
        self.image_analyzer = QRImageContextAnalyzer()
        self.temporal_model = TemporalURLRiskModel()
        self.payload_analyzer = QRPayloadAnalyzer()
        self.fusion_engine = RiskFusionEngine()

    def analyze_url(
        self,
        url: str,
        include_redirect: bool = True,
        include_temporal: bool = True,
    ) -> dict[str, Any]:
        """Analyze URL through static, redirect, and temporal modules."""
        normalized_url = self._normalize_and_validate_url(url)
        static_result = self._static_url_result(normalized_url)

        redirect_result: dict[str, Any] = {
            "risk_score": 0.0,
            "skipped": True,
            "message": "Redirect analysis skipped by request.",
        }
        if include_redirect:
            redirect_result = self.redirect_analyzer.analyze(normalized_url).to_dict()
            redirect_result["skipped"] = False

        temporal_result: dict[str, Any] = {
            "risk_score": 0.0,
            "skipped": True,
            "message": "Temporal analysis skipped by request.",
        }
        if include_temporal:
            temporal_result = self.temporal_model.assess_scan(normalized_url).to_dict()
            temporal_result["skipped"] = False

        return {
            "url": normalized_url,
            "static_url_ml": static_result,
            "redirect_chain": redirect_result,
            "time_based": temporal_result,
        }

    def analyze_image_from_base64(self, image_base64: str) -> dict[str, Any]:
        """Run image-context analysis using base64 image payload."""
        image_bytes = self._decode_base64_image(image_base64)

        # Temporary file is required because current analyzer expects file paths.
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        try:
            temp_file.write(image_bytes)
            temp_file.flush()
            temp_file.close()

            result = self.image_analyzer.analyze_image(temp_file.name).to_dict()
            result["image_source"] = "base64"
            return result
        finally:
            try:
                os.unlink(temp_file.name)
            except OSError:
                pass

    def score_risk(
        self,
        static_url_risk: float,
        redirect_chain_risk: float,
        image_context_risk: float,
        time_based_risk: float,
    ) -> dict[str, Any]:
        """Fuse component risks into final normalized score and threat label."""
        fused = self.fusion_engine.fuse(
            RiskFusionInput(
                static_url_ml_risk=static_url_risk,
                redirect_chain_risk=redirect_chain_risk,
                image_context_risk=image_context_risk,
                time_based_risk=time_based_risk,
            )
        )
        return fused.to_dict()

    def explain_risk(
        self,
        url: str,
        static_url_risk: float | None = None,
        redirect_result: dict[str, Any] | None = None,
        image_result: dict[str, Any] | None = None,
        temporal_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate top contributors and human-readable decision explanation."""
        result = self.decision_explainer.explain(
            url=url,
            static_url_risk=static_url_risk,
            redirect_result=redirect_result,
            image_result=image_result,
            temporal_result=temporal_result,
        )
        return result.to_dict()

    def scan_qr(
        self,
        qr_content: str,
        qr_type: str = "url",
        image_base64: str | None = None,
        include_explanation: bool = True,
    ) -> dict[str, Any]:
        """End-to-end QR scan analysis across all modules."""
        payload_analysis_result = self.payload_analyzer.analyze(qr_content, qr_type_hint=qr_type)
        payload_analysis = payload_analysis_result.to_dict()
        is_http_payload = payload_analysis_result.payload_type == "http_https"

        if is_http_payload:
            url_analysis = self.analyze_url(
                url=payload_analysis_result.normalized_payload,
                include_redirect=True,
                include_temporal=True,
            )
        else:
            url_analysis = self._non_http_url_analysis_placeholder(payload_analysis_result)

        image_result: dict[str, Any] = {
            "risk_score": 0.0,
            "risk_classification": "Low",
            "qr_count": 0,
            "multiple_qr_detected": False,
            "qr_regions": [],
            "errors": [],
            "image_source": "none",
            "message": "No image payload provided.",
        }

        if image_base64:
            image_result = self.analyze_image_from_base64(image_base64)

        static_risk = float(url_analysis["static_url_ml"].get("risk_score", 0.0))
        redirect_risk = float(url_analysis["redirect_chain"].get("risk_score", 0.0))
        time_risk = float(url_analysis["time_based"].get("risk_score", 0.0))
        image_risk = float(image_result.get("risk_score", 0.0))

        fused = self.score_risk(
            static_url_risk=static_risk,
            redirect_chain_risk=redirect_risk,
            image_context_risk=image_risk,
            time_based_risk=time_risk,
        )

        explanation = None
        if include_explanation:
            if is_http_payload:
                explanation = self.explain_risk(
                    url=url_analysis["url"],
                    static_url_risk=static_risk,
                    redirect_result=url_analysis["redirect_chain"],
                    image_result=image_result,
                    temporal_result=url_analysis["time_based"],
                )
            else:
                explanation = self._explain_non_http_payload(
                    payload_analysis_result=payload_analysis_result,
                    fused=fused,
                    image_result=image_result,
                )

        action_map = (
            {
                "Safe": "allow",
                "Suspicious": "warn",
                "Malicious": "block",
            }
            if is_http_payload
            else {
                "Safe": "allow",
                "Suspicious": "warn",
                "Malicious": "warn",
            }
        )
        recommended_action = action_map.get(fused.get("threat_label", ""), "warn")
        if not is_http_payload and payload_analysis_result.warnings:
            # Non-http payment/intent payloads are advisory: warn instead of block.
            recommended_action = "warn"

        resolved_payload = payload_analysis_result.normalized_payload or (qr_content or "").strip()

        return {
            "qr_type": qr_type,
            "payload_type": payload_analysis_result.payload_type,
            "qr_content": qr_content,
            "resolved_payload": resolved_payload,
            "resolved_url": url_analysis["url"] if is_http_payload else resolved_payload,
            "warning_only": not is_http_payload,
            "recommended_action": recommended_action,
            "risk": fused,
            "analysis": {
                "static_url_ml": url_analysis["static_url_ml"],
                "redirect_chain": url_analysis["redirect_chain"],
                "image_context": image_result,
                "time_based": url_analysis["time_based"],
                "payload_structural": payload_analysis,
            },
            "explanation": explanation,
        }

    @staticmethod
    def _non_http_url_analysis_placeholder(payload_analysis_result: QRPayloadAnalysisResult) -> dict[str, Any]:
        return {
            "url": "",
            "static_url_ml": {
                "risk_score": payload_analysis_result.risk_score,
                "predicted_label": "payload_structural",
                "predicted_class": None,
                "features": {
                    "payload_type": payload_analysis_result.payload_type,
                },
                "errors": [],
                "message": (
                    "HTTP URL analysis skipped. Using payload-structure heuristics "
                    "for non-http QR content."
                ),
            },
            "redirect_chain": {
                "risk_score": 0.0,
                "skipped": True,
                "message": "Redirect analysis supports only http/https payloads.",
            },
            "time_based": {
                "risk_score": 0.0,
                "skipped": True,
                "message": "Temporal URL analysis supports only http/https payloads.",
            },
        }

    @staticmethod
    def _explain_non_http_payload(
        payload_analysis_result: QRPayloadAnalysisResult,
        fused: dict[str, Any],
        image_result: dict[str, Any],
    ) -> dict[str, Any]:
        weighted = dict(fused.get("weighted_contributions", {}))
        component_risks = dict(fused.get("component_risks", {}))
        payload_bucket = float(weighted.get("static_url_ml", 0.0))

        top_signals = sorted(payload_analysis_result.signals, key=lambda item: item.weight, reverse=True)[:3]
        total_weight = sum(max(0.0, item.weight) for item in top_signals) or 1.0

        top_contributors: list[dict[str, Any]] = []
        for signal in top_signals:
            contribution = payload_bucket * (max(0.0, signal.weight) / total_weight)
            top_contributors.append(
                {
                    "feature": signal.code,
                    "source": "payload_structural",
                    "contribution_0_1": round(contribution, 6),
                    "detail": signal.detail,
                }
            )

        image_risk = float(image_result.get("risk_score", 0.0))
        if image_risk > 0 and len(top_contributors) < 3:
            image_bucket = float(weighted.get("image_context", 0.0))
            top_contributors.append(
                {
                    "feature": "image_context_risk",
                    "source": "image_context",
                    "contribution_0_1": round(image_bucket, 6),
                    "detail": f"Image-context scanner reported risk score {image_risk:.2f}.",
                }
            )

        reasons = payload_analysis_result.warnings[:2]
        if reasons:
            explanation = "Flagged for caution because " + " and ".join(reasons) + "."
        else:
            explanation = (
                "No strong structural or social-engineering risk indicators were found in this payload."
            )
        explanation += " This assessment is advisory and does not block payment execution."

        return {
            "final_risk_score_0_100": float(fused.get("final_risk_score_0_100", 0.0)),
            "threat_label": str(fused.get("threat_label", "Safe")),
            "top_contributors": top_contributors,
            "explanation": explanation,
            "component_risks": component_risks,
            "component_weighted_contributions": weighted,
            "errors": list(payload_analysis_result.errors),
        }

    def _static_url_result(self, url: str) -> dict[str, Any]:
        if self.static_inference is None:
            return {
                "risk_score": 0.0,
                "predicted_label": "unknown",
                "predicted_class": None,
                "features": {},
                "errors": [self.static_model_error or "Static model unavailable."],
            }

        prediction = self.static_inference.predict_one(url)
        return {
            "risk_score": float(prediction.get("malicious_probability", 0.0)),
            "predicted_label": prediction.get("predicted_label"),
            "predicted_class": prediction.get("predicted_class"),
            "features": prediction.get("features", {}),
            "errors": [],
        }

    def _decode_base64_image(self, image_base64: str) -> bytes:
        raw = image_base64.strip()
        if raw.startswith("data:"):
            _, _, raw = raw.partition(",")
        if len(raw) > (self.max_image_bytes * 2):
            raise HTTPException(status_code=413, detail="Image payload is too large.")
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=422, detail="Invalid base64 image payload.") from None
        if not decoded:
            raise HTTPException(status_code=422, detail="Decoded image payload is empty.")
        if len(decoded) > self.max_image_bytes:
            raise HTTPException(status_code=413, detail="Decoded image exceeds maximum allowed size.")
        return decoded

    @staticmethod
    def _extract_url_from_qr_content(qr_content: str, qr_type: str = "url") -> str:
        content = (qr_content or "").strip()
        if not content:
            raise HTTPException(status_code=422, detail="qr_content cannot be empty.")

        if qr_type == "url":
            return content

        match = URL_PATTERN.search(content)
        if not match:
            raise HTTPException(
                status_code=422,
                detail="No URL found in QR text content. Provide qr_type='url' or include a URL in text.",
            )
        return match.group(1)

    @staticmethod
    def _is_disallowed_ip(host: str) -> bool:
        try:
            parsed_ip = ip_address(host.strip("[]"))
        except ValueError:
            return False
        return (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_reserved
            or parsed_ip.is_unspecified
        )

    @classmethod
    def _normalize_and_validate_url(cls, url: str) -> str:
        candidate = (url or "").strip()
        if not candidate:
            raise HTTPException(status_code=422, detail="url cannot be empty.")

        parsed = urlsplit(candidate)
        if not parsed.scheme:
            candidate = f"http://{candidate}"
            parsed = urlsplit(candidate)

        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_URL_SCHEMES:
            raise HTTPException(status_code=422, detail="Only http/https URLs are allowed.")
        if not parsed.hostname:
            raise HTTPException(status_code=422, detail="URL must include a hostname.")
        if parsed.username or parsed.password:
            raise HTTPException(status_code=422, detail="URLs with embedded credentials are not allowed.")

        host = parsed.hostname.lower()
        if host in DISALLOWED_HOSTS or cls._is_disallowed_ip(host):
            raise HTTPException(status_code=422, detail="Target host is not allowed.")

        try:
            addrinfo = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80))
        except OSError:
            # Allow unresolved public hostnames so analysis can continue and
            # downstream network modules report best-effort errors instead of
            # failing the entire request.
            return candidate

        for _, _, _, _, sockaddr in addrinfo:
            ip_text = str(sockaddr[0]).split("%")[0]
            if cls._is_disallowed_ip(ip_text):
                raise HTTPException(
                    status_code=422,
                    detail="URL hostname resolves to a disallowed network address.",
                )

        return candidate


@lru_cache
def get_qrshield_service() -> QRShieldService:
    """Singleton service container for FastAPI dependency injection."""
    settings = get_settings()
    return QRShieldService(
        static_model_path=settings.static_model_path,
        max_image_bytes=settings.max_image_bytes,
    )
