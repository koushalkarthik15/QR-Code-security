"""Authentication helpers for FastAPI routes."""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from app.core.settings import get_settings


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """Require a valid API key for protected endpoints."""
    expected = get_settings().api_key
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )
