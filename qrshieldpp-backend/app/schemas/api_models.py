"""Request/response schemas for QRShield++ FastAPI endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class AnalyzeURLRequest(BaseModel):
    """Input payload for /analyze/url."""

    url: str = Field(..., min_length=1, max_length=4096)
    include_redirect: bool = True
    include_temporal: bool = True


class ScanQRRequest(BaseModel):
    """Input payload for /scan/qr."""

    qr_content: str = Field(..., min_length=1, max_length=8192)
    qr_type: Literal["url", "text", "auto"] = "auto"
    image_base64: str | None = Field(default=None, max_length=8_000_000)
    include_explanation: bool = True


class RiskScoreRequest(BaseModel):
    """Input payload for /risk/score."""

    static_url_risk: float = Field(..., ge=0.0, le=100.0)
    redirect_chain_risk: float = Field(..., ge=0.0, le=100.0)
    image_context_risk: float = Field(..., ge=0.0, le=100.0)
    time_based_risk: float = Field(..., ge=0.0, le=100.0)


class RiskExplainRequest(BaseModel):
    """Input payload for /risk/explain."""

    url: str = Field(..., min_length=1, max_length=4096)
    static_url_risk: float | None = Field(default=None, ge=0.0, le=100.0)
    redirect_result: dict[str, Any] | None = None
    image_result: dict[str, Any] | None = None
    temporal_result: dict[str, Any] | None = None


class APIEnvelope(BaseModel):
    """Standard JSON envelope for all endpoint responses."""

    status: Literal["success"]
    request_id: str
    timestamp_utc: str
    data: dict[str, Any]


class APIErrorEnvelope(BaseModel):
    """Standard JSON envelope for errors."""

    status: Literal["error"]
    request_id: str
    timestamp_utc: str
    error: dict[str, Any]
