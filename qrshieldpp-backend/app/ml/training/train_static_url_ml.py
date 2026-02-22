"""Train the Static URL ML layer for QRShield++.

What this script does:
1. Loads a dataset (CSV/Parquet) with URL + label columns.
2. Trains:
   - Baseline model: Logistic Regression
   - Final model: Random Forest
3. Evaluates both models with accuracy, precision, recall, and F1.
4. Saves trained models with Joblib and writes metrics/metadata to JSON.

Example:
    python app/ml/training/train_static_url_ml.py ^
      --dataset-path ..\\qrshieldpp-dataset\\data\\raw\\url_samples.csv ^
      --output-dir app\\ml\\models\\static_url
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    from app.ml.features.url_features import URLFeatureExtractor, URLFeatureTransformer
except ModuleNotFoundError:
    # Allows running this file directly without `python -m`.
    sys.path.append(str(Path(__file__).resolve().parents[3]))
    from app.ml.features.url_features import URLFeatureExtractor, URLFeatureTransformer


LABEL_TO_INT: dict[str, int] = {"benign": 0, "malicious": 1}
INT_TO_LABEL: dict[int, str] = {0: "benign", 1: "malicious"}


def _load_dataframe(dataset_path: Path) -> pd.DataFrame:
    """Load a dataset from CSV or Parquet."""
    suffix = dataset_path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(dataset_path)
    if suffix == ".parquet":
        return pd.read_parquet(dataset_path)
    raise ValueError(f"Unsupported dataset extension: {suffix}. Use .csv or .parquet.")


def _prepare_training_data(
    df: pd.DataFrame,
    url_column: str,
    label_column: str,
) -> tuple[pd.Series, pd.Series, str]:
    """Filter rows and map labels for binary malicious URL classification."""
    resolved_url_column = url_column
    if resolved_url_column not in df.columns:
        # Fallback for partially prepared datasets.
        if url_column == "url_canonical" and "url_raw" in df.columns:
            resolved_url_column = "url_raw"
        else:
            raise ValueError(
                f"URL column '{url_column}' was not found in dataset columns: {list(df.columns)}"
            )

    if label_column not in df.columns:
        raise ValueError(
            f"Label column '{label_column}' was not found in dataset columns: {list(df.columns)}"
        )

    work = df[[resolved_url_column, label_column]].copy()
    work[resolved_url_column] = work[resolved_url_column].fillna("").astype(str).str.strip()
    work[label_column] = work[label_column].fillna("").astype(str).str.lower().str.strip()

    # Keep only the supervised binary classes for this layer.
    work = work[work[label_column].isin(LABEL_TO_INT.keys())]
    work = work[work[resolved_url_column] != ""]

    if work.empty:
        raise ValueError(
            "No trainable rows found. Ensure dataset has non-empty URLs and labels in "
            "{'benign', 'malicious'}."
        )

    class_counts = work[label_column].value_counts()
    if class_counts.shape[0] < 2:
        raise ValueError("Training requires both 'benign' and 'malicious' labels.")
    if int(class_counts.min()) < 2:
        raise ValueError("Each class needs at least 2 rows for a stratified split.")

    X = work[resolved_url_column]
    y = work[label_column].map(LABEL_TO_INT)
    return X, y, resolved_url_column


def _build_logistic_baseline(random_state: int) -> Pipeline:
    """Baseline model: URL features -> standardization -> logistic regression."""
    return Pipeline(
        steps=[
            ("features", URLFeatureTransformer()),
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=random_state,
                ),
            ),
        ]
    )


def _build_random_forest_final(random_state: int) -> Pipeline:
    """Final model: URL features -> random forest classifier."""
    return Pipeline(
        steps=[
            ("features", URLFeatureTransformer()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=400,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=random_state,
                ),
            ),
        ]
    )


def _evaluate_model(model: Pipeline, X_test: pd.Series, y_test: pd.Series) -> dict[str, float]:
    """Return required binary metrics for one trained model."""
    y_pred = model.predict(X_test)
    return {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def train_static_url_layer(
    dataset_path: Path,
    output_dir: Path,
    url_column: str = "url_canonical",
    label_column: str = "label",
    test_size: float = 0.2,
    random_state: int = 42,
    feature_dictionary_path: Path | None = None,
) -> dict[str, Any]:
    """Train, evaluate, and persist QRShield++ static URL models."""
    df = _load_dataframe(dataset_path)
    X, y, resolved_url_column = _prepare_training_data(df, url_column=url_column, label_column=label_column)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    logistic_baseline = _build_logistic_baseline(random_state=random_state)
    logistic_baseline.fit(X_train, y_train)
    logistic_metrics = _evaluate_model(logistic_baseline, X_test, y_test)

    random_forest_final = _build_random_forest_final(random_state=random_state)
    random_forest_final.fit(X_train, y_train)
    random_forest_metrics = _evaluate_model(random_forest_final, X_test, y_test)

    output_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = output_dir / "logistic_regression_baseline.joblib"
    final_path = output_dir / "random_forest_final.joblib"

    joblib.dump(logistic_baseline, baseline_path)
    joblib.dump(random_forest_final, final_path)

    feature_names = URLFeatureExtractor.feature_names()
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(dataset_path),
        "resolved_url_column": resolved_url_column,
        "label_column": label_column,
        "label_mapping": LABEL_TO_INT,
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "metrics": {
            "logistic_regression_baseline": logistic_metrics,
            "random_forest_final": random_forest_metrics,
        },
        "artifacts": {
            "baseline_model": str(baseline_path),
            "final_model": str(final_path),
        },
    }

    _write_json(output_dir / "metrics.json", metadata["metrics"])
    _write_json(output_dir / "training_metadata.json", metadata)

    # Optional update of the dataset feature dictionary artifact.
    if feature_dictionary_path is not None:
        feature_dictionary = {
            "version": "1.0.0",
            "description": "QRShield++ static URL ML feature dictionary",
            "lexical_features": URLFeatureExtractor.LEXICAL_FEATURES,
            "statistical_features": URLFeatureExtractor.STATISTICAL_FEATURES,
            "created_for": "malicious URL detection from QR payloads",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        _write_json(feature_dictionary_path, feature_dictionary)

    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train QRShield++ static URL ML models.")
    parser.add_argument("--dataset-path", required=True, help="Path to CSV or Parquet dataset.")
    parser.add_argument(
        "--output-dir",
        default="app/ml/models/static_url",
        help="Directory for saved model artifacts.",
    )
    parser.add_argument(
        "--url-column",
        default="url_canonical",
        help="Input URL column name.",
    )
    parser.add_argument(
        "--label-column",
        default="label",
        help="Label column name.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split ratio (0-1).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    parser.add_argument(
        "--feature-dictionary-path",
        default=None,
        help="Optional path to write feature_dictionary.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metadata = train_static_url_layer(
        dataset_path=Path(args.dataset_path),
        output_dir=Path(args.output_dir),
        url_column=args.url_column,
        label_column=args.label_column,
        test_size=args.test_size,
        random_state=args.random_state,
        feature_dictionary_path=(
            Path(args.feature_dictionary_path) if args.feature_dictionary_path else None
        ),
    )

    print("Training completed.")
    print(json.dumps(metadata["metrics"], indent=2))
    print(f"Final model: {metadata['artifacts']['final_model']}")


if __name__ == "__main__":
    main()

