"""Inference helpers for the QRShield++ static URL ML layer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np

try:
    from app.ml.features.url_features import URLFeatureExtractor
except ModuleNotFoundError:
    # Allows running this file directly without `python -m`.
    sys.path.append(str(Path(__file__).resolve().parents[3]))
    from app.ml.features.url_features import URLFeatureExtractor


INT_TO_LABEL: dict[int, str] = {0: "benign", 1: "malicious"}


class StaticURLModelInference:
    """Load a saved static URL model and predict malicious URL risk."""

    def __init__(self, model_path: Path) -> None:
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found at: {self.model_path}")
        self.model = joblib.load(self.model_path)

    def predict_one(self, url: str) -> dict[str, Any]:
        """Predict one URL and return score, label, and extracted features."""
        prediction = int(self.model.predict([url])[0])
        proba_malicious = self._predict_proba_malicious([url])[0]

        return {
            "url": url,
            "predicted_label": INT_TO_LABEL.get(prediction, str(prediction)),
            "predicted_class": prediction,
            "malicious_probability": float(proba_malicious),
            "features": URLFeatureExtractor.extract_features(url),
        }

    def predict_batch(self, urls: Sequence[str]) -> list[dict[str, Any]]:
        """Predict multiple URLs at once."""
        urls_list = list(urls)
        predictions = self.model.predict(urls_list)
        probabilities = self._predict_proba_malicious(urls_list)

        results: list[dict[str, Any]] = []
        for idx, url in enumerate(urls_list):
            label_int = int(predictions[idx])
            results.append(
                {
                    "url": url,
                    "predicted_label": INT_TO_LABEL.get(label_int, str(label_int)),
                    "predicted_class": label_int,
                    "malicious_probability": float(probabilities[idx]),
                }
            )
        return results

    def _predict_proba_malicious(self, urls: Sequence[str]) -> np.ndarray:
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(list(urls))
            # Binary model convention: class 1 = malicious.
            if proba.shape[1] > 1:
                return proba[:, 1]
            return proba[:, 0]
        # Fallback for estimators without probability support.
        return np.array([float(pred) for pred in self.model.predict(list(urls))], dtype=float)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run inference with a saved static URL model.")
    parser.add_argument("--model-path", required=True, help="Path to *.joblib model artifact.")
    parser.add_argument("--url", required=True, help="URL to score.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    runner = StaticURLModelInference(model_path=Path(args.model_path))
    result = runner.predict_one(args.url)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

