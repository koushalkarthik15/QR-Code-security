"""FastAPI endpoints for QRShield++ detection workflows."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends
from starlette.concurrency import run_in_threadpool

from app.core.auth import require_api_key
from app.core.services import QRShieldService, get_qrshield_service
from app.schemas.api_models import (
    APIEnvelope,
    AnalyzeURLRequest,
    RiskExplainRequest,
    RiskScoreRequest,
    ScanQRRequest,
)


router = APIRouter(
    tags=["QRShield++"],
    dependencies=[Depends(require_api_key)],
)


def _envelope(data: dict) -> dict:
    return {
        "status": "success",
        "request_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


@router.post("/analyze/url", response_model=APIEnvelope)
async def analyze_url(
    payload: AnalyzeURLRequest,
    service: QRShieldService = Depends(get_qrshield_service),
) -> dict:
    """Analyze URL with static ML, redirect, and temporal layers."""
    result = await run_in_threadpool(
        service.analyze_url,
        payload.url,
        payload.include_redirect,
        payload.include_temporal,
    )
    return _envelope(result)


@router.post("/risk/score", response_model=APIEnvelope)
async def risk_score(
    payload: RiskScoreRequest,
    service: QRShieldService = Depends(get_qrshield_service),
) -> dict:
    """Fuse module risks into final score + threat label."""
    result = await run_in_threadpool(
        service.score_risk,
        payload.static_url_risk,
        payload.redirect_chain_risk,
        payload.image_context_risk,
        payload.time_based_risk,
    )
    return _envelope(result)


@router.post("/risk/explain", response_model=APIEnvelope)
async def risk_explain(
    payload: RiskExplainRequest,
    service: QRShieldService = Depends(get_qrshield_service),
) -> dict:
    """Generate explainable final decision with top contributors."""
    result = await run_in_threadpool(
        service.explain_risk,
        payload.url,
        payload.static_url_risk,
        payload.redirect_result,
        payload.image_result,
        payload.temporal_result,
    )
    return _envelope(result)


@router.post("/scan/qr", response_model=APIEnvelope)
async def scan_qr(
    payload: ScanQRRequest,
    service: QRShieldService = Depends(get_qrshield_service),
) -> dict:
    """End-to-end QR scan endpoint for web/mobile clients."""
    result = await run_in_threadpool(
        service.scan_qr,
        payload.qr_content,
        payload.qr_type,
        payload.image_base64,
        payload.include_explanation,
    )
    return _envelope(result)
