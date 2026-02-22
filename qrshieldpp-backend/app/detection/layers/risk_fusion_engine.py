"""Risk fusion engine for QRShield++.

Combines four normalized risk signals:
- Static URL ML risk
- Redirect-chain risk
- Image-context risk
- Time-based risk

Default weighted aggregation:
0.35 * URL + 0.25 * Redirect + 0.20 * Image + 0.20 * Time
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RiskFusionInput:
    """Inputs for fusion. Preferred range for each value is [0.0, 1.0]."""

    static_url_ml_risk: float
    redirect_chain_risk: float
    image_context_risk: float
    time_based_risk: float


@dataclass
class RiskFusionResult:
    """Output of weighted risk fusion."""

    component_risks: dict[str, float]
    weighted_contributions: dict[str, float]
    fusion_score_0_1: float
    final_risk_score_0_100: float
    threat_label: str
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to JSON-friendly dictionary."""
        return asdict(self)


class RiskFusionEngine:
    """Weighted risk fusion engine with threat label assignment."""

    def __init__(
        self,
        url_weight: float = 0.35,
        redirect_weight: float = 0.25,
        image_weight: float = 0.20,
        time_weight: float = 0.20,
        safe_threshold: float = 33.0,
        malicious_threshold: float = 66.0,
        allow_percentage_inputs: bool = True,
    ) -> None:
        self.url_weight = url_weight
        self.redirect_weight = redirect_weight
        self.image_weight = image_weight
        self.time_weight = time_weight
        self.safe_threshold = safe_threshold
        self.malicious_threshold = malicious_threshold
        self.allow_percentage_inputs = allow_percentage_inputs

        total_weight = self.url_weight + self.redirect_weight + self.image_weight + self.time_weight
        if abs(total_weight - 1.0) > 1e-9:
            raise ValueError(f"Fusion weights must sum to 1.0, got {total_weight:.6f}")
        if not (0.0 <= self.safe_threshold < self.malicious_threshold <= 100.0):
            raise ValueError("Thresholds must satisfy 0 <= safe < malicious <= 100.")

    def fuse(self, fusion_input: RiskFusionInput) -> RiskFusionResult:
        """Fuse the four component risks into final score and threat label."""
        errors: list[str] = []

        url_risk = self._normalize_input_risk(fusion_input.static_url_ml_risk, "static_url_ml_risk", errors)
        redirect_risk = self._normalize_input_risk(
            fusion_input.redirect_chain_risk, "redirect_chain_risk", errors
        )
        image_risk = self._normalize_input_risk(fusion_input.image_context_risk, "image_context_risk", errors)
        time_risk = self._normalize_input_risk(fusion_input.time_based_risk, "time_based_risk", errors)

        weighted_contributions = {
            "static_url_ml": round(self.url_weight * url_risk, 6),
            "redirect_chain": round(self.redirect_weight * redirect_risk, 6),
            "image_context": round(self.image_weight * image_risk, 6),
            "time_based": round(self.time_weight * time_risk, 6),
        }

        fusion_score = (
            weighted_contributions["static_url_ml"]
            + weighted_contributions["redirect_chain"]
            + weighted_contributions["image_context"]
            + weighted_contributions["time_based"]
        )
        fusion_score = round(self._clip01(fusion_score), 6)

        final_score = round(fusion_score * 100.0, 2)
        threat_label = self._label_from_score(final_score)

        return RiskFusionResult(
            component_risks={
                "static_url_ml": round(url_risk, 6),
                "redirect_chain": round(redirect_risk, 6),
                "image_context": round(image_risk, 6),
                "time_based": round(time_risk, 6),
            },
            weighted_contributions=weighted_contributions,
            fusion_score_0_1=fusion_score,
            final_risk_score_0_100=final_score,
            threat_label=threat_label,
            errors=errors,
        )

    def _normalize_input_risk(self, value: float, name: str, errors: list[str]) -> float:
        """Normalize one input risk to [0, 1].

        Accepted forms:
        - ratio in [0,1]
        - percentage in [0,100] if allow_percentage_inputs=True
        """
        try:
            raw = float(value)
        except (TypeError, ValueError):
            errors.append(f"{name} is not numeric: {value!r}. Using 1.0.")
            return 1.0

        if 0.0 <= raw <= 1.0:
            return raw

        if self.allow_percentage_inputs and 0.0 <= raw <= 100.0:
            return raw / 100.0

        errors.append(f"{name} out of range ({raw}). Clamped to [0,1].")
        return self._clip01(raw)

    def _label_from_score(self, score_0_100: float) -> str:
        """Map final score to Safe / Suspicious / Malicious."""
        if score_0_100 < self.safe_threshold:
            return "Safe"
        if score_0_100 < self.malicious_threshold:
            return "Suspicious"
        return "Malicious"

    @staticmethod
    def _clip01(value: float) -> float:
        return max(0.0, min(1.0, float(value)))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fuse QRShield++ component risks.")
    parser.add_argument("--url-risk", required=True, type=float, help="Static URL ML risk.")
    parser.add_argument("--redirect-risk", required=True, type=float, help="Redirect-chain risk.")
    parser.add_argument("--image-risk", required=True, type=float, help="Image-context risk.")
    parser.add_argument("--time-risk", required=True, type=float, help="Time-based risk.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    engine = RiskFusionEngine()
    result = engine.fuse(
        RiskFusionInput(
            static_url_ml_risk=args.url_risk,
            redirect_chain_risk=args.redirect_risk,
            image_context_risk=args.image_risk,
            time_based_risk=args.time_risk,
        )
    )
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

