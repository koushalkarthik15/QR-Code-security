"""API router composition for version 1."""

from fastapi import APIRouter

from app.api.v1.routes.qrshield import router as qrshield_router


api_router = APIRouter()
api_router.include_router(qrshield_router)

