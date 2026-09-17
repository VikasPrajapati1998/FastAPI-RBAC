"""Aggregates every version 1 router into a single mountable router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import auth, items, users

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(items.router)

__all__ = ["api_router"]
