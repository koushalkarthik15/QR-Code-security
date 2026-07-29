"""FastAPI application entrypoint for QRShield++ backend."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.services import get_qrshield_service
from app.core.settings import get_settings


# Configure structured logging for production
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("qrshieldpp.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the FastAPI application."""
    logger.info("Starting QRShield++ Backend...")
    # Warm singleton service and model(s) once at startup.
    get_qrshield_service()
    logger.info("QRShield++ Service and models loaded successfully.")
    yield
    logger.info("Shutting down QRShield++ Backend...")


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="QRShield++ threat detection backend for web and mobile clients.",
    lifespan=lifespan,
)

# CORS Configuration
# Restricting to known frontend deployment URL and allowing mobile clients (which might not send origin, or we can use * if required for mobile)
# For security, we specify the exact Vercel frontend URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://qr-code-security-6caq.vercel.app",
        "http://localhost:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.middleware("http")
async def logging_middleware(request: Request, call_next: Any) -> Response:
    """Structured logging middleware to track request duration and status."""
    start_time = time.perf_counter()
    request_id = str(uuid4())
    
    # Do not log query params or bodies to avoid leaking QR payloads or images
    logger.info(f"Request started: {request_id} | {request.method} {request.url.path}")
    
    try:
        response = await call_next(request)
        process_time = time.perf_counter() - start_time
        logger.info(f"Request completed: {request_id} | {request.method} {request.url.path} | Status: {response.status_code} | Duration: {process_time:.4f}s")
        response.headers["X-Request-ID"] = request_id
        return response
    except Exception as exc:
        process_time = time.perf_counter() - start_time
        logger.error(f"Request failed: {request_id} | {request.method} {request.url.path} | Duration: {process_time:.4f}s | Error: {str(exc)}")
        raise


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
    logger.exception("Unhandled exception occurred.")
    return _error_response(
        status_code=500,
        message="Internal server error.",
        details=None,
    )


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


@app.get("/ready")
async def ready() -> dict[str, Any]:
    """Readiness probe to ensure models are loaded."""
    try:
        service = get_qrshield_service()
        if service.static_model_error:
            return {"status": "degraded", "message": service.static_model_error}
        return {"status": "ready"}
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}
