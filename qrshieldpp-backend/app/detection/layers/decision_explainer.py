"""Explainable decision layer for QRShield++.

This module combines:
- Static URL ML attribution (SHAP if available, otherwise model-based attribution)
- Redirect-chain findings
- Image-context findings
- Time-based findings

Output includes:
- Final fused score (0-100)
- Threat label
- Top 3 contributing features
- Human-readable explanation sentence
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

try:
    from app.detection.layers.risk_fusion_engine import RiskFusionEngine, RiskFusionInput
    from app.ml.features.url_features import URLFeatureExtractor
except ModuleNotFoundError:
    # Allows running this file directly without `python -m`.
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[3]))
    from app.detection.layers.risk_fusion_engine import RiskFusionEngine, RiskFusionInput
    from app.ml.features.url_features import URLFeatureExtractor


@dataclass
class ExplainedFeature:
    """One explainability contribution item."""

    feature: str
    source: str
    contribution_0_1: float
    detail: str


@dataclass
class DecisionExplanationResult:
    """Full explainability output for one final decision."""

    final_risk_score_0_100: float
    threat_label: str
    top_contributors: list[ExplainedFeature]
    explanation: str
    component_risks: dict[str, float]
    component_weighted_contributions: dict[str, float]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["top_contributors"] = [asdict(item) for item in self.top_contributors]
        return payload


class StaticURLAttributionEngine:
    """Model attribution for static URL risk."""

    def __init__(self, model: Any | None = None, model_path: str | None = None) -> None:
        if model is not None:
            self.model = model
        elif model_path:
            self.model = joblib.load(model_path)
        else:
            self.model = None

    def predict_risk(self, url: str) -> float | None:
        """Return malicious probability if a model is available."""
        if self.model is None:
            return None
        if not hasattr(self.model, "predict_proba"):
            return None
        try:
            proba = self.model.predict_proba([url])
            if proba.shape[1] > 1:
                return float(proba[0, 1])
            return float(proba[0, 0])
        except Exception:  # noqa: BLE001
            return None

    def top_feature_attributions(
        self,
        url: str,
        top_k: int = 3,
    ) -> tuple[list[tuple[str, float, float]], list[str]]:
        """Return top feature attributions as (name, value, signed_contribution)."""
        errors: list[str] = []
        features = URLFeatureExtractor.extract_features(url)
        feature_names = list(features.keys())
        x_row = np.array([[features[name] for name in feature_names]], dtype=np.float64)

        if self.model is None:
            return [], errors

        classifier = self._extract_classifier(self.model)
        if classifier is None:
            errors.append("Unable to identify classifier from static URL model.")
            return [], errors

        # 1) Try SHAP first.
        shap_contrib = self._shap_contributions(classifier, x_row)
        if shap_contrib is not None:
            ranked = self._rank_contributions(feature_names, x_row[0], shap_contrib, top_k)
            return ranked, errors

        # 2) Fallback to deterministic feature attribution.
        fallback_contrib = self._fallback_contributions(classifier, x_row)
        if fallback_contrib is None:
            errors.append("No SHAP backend and no fallback attribution available.")
            return [], errors
        ranked = self._rank_contributions(feature_names, x_row[0], fallback_contrib, top_k)
        return ranked, errors

    @staticmethod
    def _extract_classifier(model: Any) -> Any | None:
        # scikit-learn pipeline support.
        if hasattr(model, "named_steps") and "classifier" in model.named_steps:
            return model.named_steps["classifier"]
        return model

    @staticmethod
    def _rank_contributions(
        feature_names: list[str],
        feature_values: np.ndarray,
        contributions: np.ndarray,
        top_k: int,
    ) -> list[tuple[str, float, float]]:
        values = np.asarray(contributions, dtype=np.float64).reshape(-1)
        if values.shape[0] != len(feature_names):
            return []
        order = np.argsort(np.abs(values))[::-1]
        ranked: list[tuple[str, float, float]] = []
        for idx in order[: max(1, top_k)]:
            ranked.append((feature_names[int(idx)], float(feature_values[int(idx)]), float(values[int(idx)])))
        return ranked

    @staticmethod
    def _shap_contributions(classifier: Any, x_row: np.ndarray) -> np.ndarray | None:
        try:
            import shap  # type: ignore
        except Exception:  # noqa: BLE001
            return None

        try:
            explainer = shap.TreeExplainer(classifier)
            shap_values = explainer.shap_values(x_row)
        except Exception:  # noqa: BLE001
            return None

        # SHAP binary format can be list[class0, class1] or ndarray.
        if isinstance(shap_values, list):
            if len(shap_values) < 2:
                return None
            return np.asarray(shap_values[1]).reshape(-1)

        arr = np.asarray(shap_values)
        if arr.ndim == 3:  # (n_samples, n_outputs, n_features)
            return arr[0, -1, :]
        if arr.ndim == 2:  # (n_samples, n_features)
            return arr[0, :]
        return None

    @staticmethod
    def _fallback_contributions(classifier: Any, x_row: np.ndarray) -> np.ndarray | None:
        # Logistic/linear family.
        if hasattr(classifier, "coef_"):
            coef = np.asarray(classifier.coef_)
            if coef.ndim == 2:
                coef = coef[0]
            return coef * x_row.reshape(-1)

        # Tree-family fallback: global importances weighted by local magnitude.
        if hasattr(classifier, "feature_importances_"):
            imp = np.asarray(classifier.feature_importances_).reshape(-1)
            x_abs = np.abs(x_row.reshape(-1))
            denom = float(np.sum(x_abs)) if np.sum(x_abs) > 0 else 1.0
            local_weight = x_abs / denom
            return imp * (0.5 + 0.5 * local_weight)

        return None


class QRShieldDecisionExplainer:
    """Generate top contributors and natural-language explanation."""

    def __init__(self, static_url_model: Any | None = None, static_url_model_path: str | None = None) -> None:
        self.url_attribution = StaticURLAttributionEngine(
            model=static_url_model,
            model_path=static_url_model_path,
        )
        self.fusion_engine = RiskFusionEngine()

    def explain(
        self,
        url: str,
        static_url_risk: float | None = None,
        redirect_result: dict[str, Any] | None = None,
        image_result: dict[str, Any] | None = None,
        temporal_result: dict[str, Any] | None = None,
    ) -> DecisionExplanationResult:
        errors: list[str] = []

        predicted_url_risk = static_url_risk
        if predicted_url_risk is None:
            predicted_url_risk = self.url_attribution.predict_risk(url)
        if predicted_url_risk is None:
            predicted_url_risk = 0.0
            errors.append("Static URL model unavailable; URL risk defaulted to 0.0.")

        redirect_risk = float((redirect_result or {}).get("risk_score", 0.0))
        image_risk = float((image_result or {}).get("risk_score", 0.0))
        time_risk = float((temporal_result or {}).get("risk_score", 0.0))

        fused = self.fusion_engine.fuse(
            RiskFusionInput(
                static_url_ml_risk=predicted_url_risk,
                redirect_chain_risk=redirect_risk,
                image_context_risk=image_risk,
                time_based_risk=time_risk,
            )
        )
        errors.extend(fused.errors)

        candidates: list[ExplainedFeature] = []
        weighted = fused.weighted_contributions
        component_risks = fused.component_risks

        # URL model attributions.
        url_attrib, attrib_errors = self.url_attribution.top_feature_attributions(url, top_k=5)
        errors.extend(attrib_errors)
        url_bucket = float(weighted.get("static_url_ml", 0.0))
        if url_attrib and url_bucket > 0:
            total_abs = sum(abs(item[2]) for item in url_attrib) or 1.0
            for feature_name, value, contribution in url_attrib:
                part = url_bucket * (abs(contribution) / total_abs)
                candidates.append(
                    ExplainedFeature(
                        feature=feature_name,
                        source="static_url_ml",
                        contribution_0_1=round(part, 6),
                        detail=self._feature_reason_text(feature_name, value),
                    )
                )

        candidates.extend(
            self._redirect_candidates(redirect_result or {}, float(weighted.get("redirect_chain", 0.0)))
        )
        candidates.extend(
            self._image_candidates(image_result or {}, float(weighted.get("image_context", 0.0)))
        )
        candidates.extend(
            self._time_candidates(temporal_result or {}, float(weighted.get("time_based", 0.0)))
        )

        if not candidates:
            candidates.append(
                ExplainedFeature(
                    feature="low_signal",
                    source="system",
                    contribution_0_1=0.0,
                    detail="No significant risk signal detected",
                )
            )

        # Merge same feature labels from multiple sources if repeated.
        merged = self._merge_candidates(candidates)
        merged.sort(key=lambda item: item.contribution_0_1, reverse=True)
        top_contributors = merged[:3]

        explanation = self._compose_explanation(
            threat_label=fused.threat_label,
            top_contributors=top_contributors,
            fallback_score=fused.final_risk_score_0_100,
        )

        return DecisionExplanationResult(
            final_risk_score_0_100=fused.final_risk_score_0_100,
            threat_label=fused.threat_label,
            top_contributors=top_contributors,
            explanation=explanation,
            component_risks=component_risks,
            component_weighted_contributions=weighted,
            errors=errors,
        )

    @staticmethod
    def _merge_candidates(candidates: list[ExplainedFeature]) -> list[ExplainedFeature]:
        merged: dict[tuple[str, str], ExplainedFeature] = {}
        for item in candidates:
            detail_key = item.detail.strip().lower()
            if detail_key:
                key = ("detail", detail_key)
            else:
                key = (item.feature, item.source)
            if key not in merged:
                merged[key] = item
            else:
                current = merged[key]
                current.contribution_0_1 = round(current.contribution_0_1 + item.contribution_0_1, 6)
                if item.source not in current.source.split("+"):
                    current.source = f"{current.source}+{item.source}"
        return list(merged.values())

    @staticmethod
    def _feature_reason_text(feature: str, value: float) -> str:
        rounded = round(float(value), 4)
        templates = {
            "suspicious_keyword_count": f"suspicious URL keywords present ({rounded})",
            "contains_shortener": "URL shortener detected",
            "has_punycode": "punycode domain pattern detected",
            "has_ip_host": "IP-based host used in URL",
            "query_param_count": f"high query complexity ({rounded} parameters)",
            "entropy_url": f"high URL entropy ({rounded})",
            "host_digit_ratio": f"unusual digit ratio in host ({rounded})",
        }
        return templates.get(feature, f"{feature} contributed ({rounded})")

    @staticmethod
    def _redirect_candidates(redirect_result: dict[str, Any], bucket: float) -> list[ExplainedFeature]:
        if bucket <= 0:
            return []

        raw: list[tuple[str, float, str]] = []
        redirects = float(redirect_result.get("redirect_count", 0.0))
        switches = float(redirect_result.get("domain_switch_count", 0.0))
        downgrade = bool(redirect_result.get("https_to_http_downgrade", False))
        domain_age = redirect_result.get("final_domain_age_days")

        if redirects > 0:
            raw.append(
                (
                    "redirect_count",
                    min(1.0, redirects / 4.0),
                    f"{int(redirects)} redirects detected",
                )
            )
        if switches > 0:
            raw.append(
                (
                    "domain_switch_count",
                    min(0.8, switches / 4.0),
                    f"{int(switches)} domain switches detected",
                )
            )
        if downgrade:
            raw.append(("https_to_http_downgrade", 0.8, "HTTPS to HTTP downgrade detected"))
        if isinstance(domain_age, (int, float)):
            if domain_age < 7:
                raw.append(("final_domain_age_days", 0.9, "domain age < 7 days"))
            elif domain_age < 30:
                raw.append(("final_domain_age_days", 0.7, "domain age < 30 days"))

        return QRShieldDecisionExplainer._distribute_bucket(raw, bucket, "redirect_chain")

    @staticmethod
    def _image_candidates(image_result: dict[str, Any], bucket: float) -> list[ExplainedFeature]:
        if bucket <= 0:
            return []

        raw: list[tuple[str, float, str]] = []
        qr_count = int(image_result.get("qr_count", 0) or 0)
        if qr_count > 1:
            raw.append(("multiple_qr_detected", min(1.0, (qr_count - 1) / 3.0), f"{qr_count} QR codes in one image"))

        regions = image_result.get("qr_regions") or []
        if isinstance(regions, list) and regions:
            max_edge = 0.0
            max_overlay = 0.0
            for region in regions:
                if not isinstance(region, dict):
                    continue
                max_edge = max(max_edge, float(region.get("edge_irregularity_score", 0.0)))
                max_overlay = max(max_overlay, float(region.get("overlay_artifact_score", 0.0)))

            if max_edge > 0:
                raw.append(("edge_irregularity_score", min(1.0, max_edge), f"edge irregularity score {max_edge:.2f}"))
            if max_overlay > 0:
                raw.append(("overlay_artifact_score", min(1.0, max_overlay), f"overlay artifact score {max_overlay:.2f}"))

        return QRShieldDecisionExplainer._distribute_bucket(raw, bucket, "image_context")

    @staticmethod
    def _time_candidates(temporal_result: dict[str, Any], bucket: float) -> list[ExplainedFeature]:
        if bucket <= 0:
            return []

        raw: list[tuple[str, float, str]] = []
        age_days = temporal_result.get("domain_age_days")
        recent_scans = float(temporal_result.get("recent_scan_count_1h", 0.0))
        decayed = float(temporal_result.get("decayed_scan_frequency", 0.0))

        if isinstance(age_days, (int, float)):
            if age_days < 7:
                raw.append(("domain_age_days", 1.0, "domain age < 7 days"))
            elif age_days < 30:
                raw.append(("domain_age_days", 0.8, "domain age < 30 days"))
            elif age_days < 90:
                raw.append(("domain_age_days", 0.55, "domain age < 90 days"))

        if recent_scans > 0:
            raw.append(
                (
                    "recent_scan_count_1h",
                    min(1.0, recent_scans / 6.0),
                    f"{int(recent_scans)} scans observed in the last hour",
                )
            )
        if decayed > 0:
            raw.append(
                (
                    "decayed_scan_frequency",
                    min(1.0, decayed / 8.0),
                    f"time-decayed scan frequency {decayed:.2f}",
                )
            )

        return QRShieldDecisionExplainer._distribute_bucket(raw, bucket, "time_based")

    @staticmethod
    def _distribute_bucket(
        raw_signals: list[tuple[str, float, str]],
        bucket: float,
        source: str,
    ) -> list[ExplainedFeature]:
        if not raw_signals:
            return []
        total_strength = sum(max(0.0, item[1]) for item in raw_signals) or 1.0
        out: list[ExplainedFeature] = []
        for name, strength, detail in raw_signals:
            contribution = bucket * (max(0.0, strength) / total_strength)
            out.append(
                ExplainedFeature(
                    feature=name,
                    source=source,
                    contribution_0_1=round(contribution, 6),
                    detail=detail,
                )
            )
        return out

    @staticmethod
    def _compose_explanation(
        threat_label: str,
        top_contributors: list[ExplainedFeature],
        fallback_score: float,
    ) -> str:
        reasons = [item.detail for item in top_contributors if item.detail]
        preferred = []
        for pattern in ("domain age", "redirects detected", "HTTPS to HTTP downgrade", "overlay", "edge"):
            for reason in reasons:
                if pattern.lower() in reason.lower() and reason not in preferred:
                    preferred.append(reason)
        for reason in reasons:
            if reason not in preferred:
                preferred.append(reason)
        reasons = preferred

        if not reasons:
            reasons = [f"fused risk score reached {fallback_score:.2f}"]

        if threat_label == "Malicious":
            return "Blocked because " + " and ".join(reasons[:2]) + "."
        if threat_label == "Suspicious":
            return "Flagged as suspicious because " + " and ".join(reasons[:2]) + "."
        return "Marked safe because no strong malicious indicators were dominant."


def _load_optional_json(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.exists():
        return None
    return json.loads(file_path.read_text(encoding="utf-8"))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Explain QRShield++ final decision.")
    parser.add_argument("--url", required=True, help="URL that was scanned.")
    parser.add_argument("--static-url-model", default=None, help="Path to static URL ML model (.joblib).")
    parser.add_argument("--static-url-risk", type=float, default=None, help="Optional precomputed URL risk [0,1].")
    parser.add_argument("--redirect-json", default=None, help="Path to redirect analyzer JSON output.")
    parser.add_argument("--image-json", default=None, help="Path to image-context analyzer JSON output.")
    parser.add_argument("--temporal-json", default=None, help="Path to temporal-risk JSON output.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    explainer = QRShieldDecisionExplainer(static_url_model_path=args.static_url_model)
    result = explainer.explain(
        url=args.url,
        static_url_risk=args.static_url_risk,
        redirect_result=_load_optional_json(args.redirect_json),
        image_result=_load_optional_json(args.image_json),
        temporal_result=_load_optional_json(args.temporal_json),
    )
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
