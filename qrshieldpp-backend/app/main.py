"""FastAPI application entrypoint for QRShield++ backend."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.services import get_qrshield_service
from app.core.settings import get_settings


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="QRShield++ threat detection backend for web and mobile clients.",
)
app.include_router(api_router)


def _error_response(
    status_code: int,
    message: str,
    details: Any | None = None,
) -> JSONResponse:
    payload = {
        "status": "error",
        "request_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "error": {
            "message": message,
            "details": details,
        },
    }
    return JSONResponse(status_code=status_code, content=payload)


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    return _error_response(
        status_code=exc.status_code,
        message=str(exc.detail),
        details=None,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return _error_response(
        status_code=422,
        message="Input validation failed.",
        details=exc.errors(),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, _exc: Exception) -> JSONResponse:
    return _error_response(
        status_code=500,
        message="Internal server error.",
        details=None,
    )


@app.on_event("startup")
async def startup_event() -> None:
    # Warm singleton service and model(s) once at startup.
    get_qrshield_service()


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "status": "success",
        "service": settings.app_name,
        "version": settings.app_version,
        "endpoints": ["/scan/qr", "/analyze/url", "/risk/score", "/risk/explain"],
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
