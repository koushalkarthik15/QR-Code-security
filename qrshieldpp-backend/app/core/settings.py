"""Application settings for QRShield++ FastAPI backend."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]


def _resolve_path(raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return ROOT_DIR / candidate


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:  # noqa: BLE001
        raise RuntimeError(f"{name} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    app_name: str
    app_version: str
    static_model_path: Path
    api_key: str
    max_image_bytes: int


def get_settings() -> Settings:
    """Create immutable application settings."""
    static_model = os.getenv(
        "QRSHIELD_STATIC_MODEL_PATH",
        "app/ml/models/static_url/random_forest_final.joblib",
    )
    api_key = (os.getenv("QRSHIELD_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError("QRSHIELD_API_KEY must be set.")

    max_image_bytes = _env_int(
        "QRSHIELD_MAX_IMAGE_BYTES",
        default=5 * 1024 * 1024,
        minimum=256 * 1024,
        maximum=25 * 1024 * 1024,
    )

    return Settings(
        app_name="QRShield++ Backend",
        app_version="1.0.0",
        static_model_path=_resolve_path(static_model),
        api_key=api_key,
        max_image_bytes=max_image_bytes,
    )
