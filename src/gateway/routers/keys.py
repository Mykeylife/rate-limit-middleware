"""Administrative API Key Lifecycle Management Router.

Provides secure orchestration operations to generate, inspect, and rotate
API key quotas and tracking tokens within the secure gateway perimeter.
"""

import datetime
import secrets
from typing import List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from gateway.database import db_manager

router = APIRouter(prefix="/api/v1/keys", tags=["API Key Administration"])


class KeyCreateRequest(BaseModel):
    """Data blueprint specifying parameters to provision an API key token."""

    owner: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="The identification name of the target consumer.",
    )
    requests_limit: int = Field(
        5,
        ge=1,
        description="Maximum rolling transactions permitted in target window.",
    )
    window_size_seconds: int = Field(
        10,
        ge=1,
        description="Sliding window size measurement tracking configurations.",
    )


class KeyStatusResponse(BaseModel):
    """Structural layout reporting configured parameters of a unique token."""

    api_key: str
    owner: str
    requests_limit: int
    window_size_seconds: int
    is_active: bool
    created_at: str


class KeyRotationRequest(BaseModel):
    """Request contract providing target key token sequences for rotation."""

    old_api_key: str = Field(
        ..., description="The compromised or expiring token key sequence."
    )


@router.post("/create", response_model=KeyStatusResponse, status_code=201)
async def generate_new_api_key(payload: KeyCreateRequest):
    """Provision random secure token and commit configuration schemas to disk."""
    token_seed = secrets.token_urlsafe(24)
    generated_key = f"sk_live_{token_seed}"

    success = db_manager.create_api_key(
        api_key=generated_key,
        owner=payload.owner,
        requests_limit=payload.requests_limit,
        window_size=payload.window_size_seconds,
    )

    if not success:
        raise HTTPException(
            status_code=500,
            detail="Database constraints prevented secure token allocation.",
        )

    return {
        "api_key": generated_key,
        "owner": payload.owner,
        "requests_limit": payload.requests_limit,
        "window_size_seconds": payload.window_size_seconds,
        "is_active": True,
        "created_at": datetime.datetime.utcnow().isoformat(),
    }


@router.get("/list", response_model=List[KeyStatusResponse])
async def list_managed_gateway_keys():
    """Retrieve runtime state records for registered system tracking tokens."""
    records = db_manager.fetch_all_keys()
    response_list = []
    for r in records:
        response_list.append(
            {
                "api_key": r["api_key"],
                "owner": r["owner"],
                "requests_limit": r["requests_limit"],
                "window_size_seconds": r["window_size_seconds"],
                "is_active": bool(r["is_active"]),
                "created_at": str(r["created_at"]),
            }
        )
    return response_list


@router.post("/rotate", response_model=KeyStatusResponse)
async def rotate_active_api_key(payload: KeyRotationRequest):
    """Deactivate existing tracking key token and replace with fresh token."""
    old_key_metadata = db_manager.fetch_key_status(payload.old_api_key)
    if not old_key_metadata:
        raise HTTPException(
            status_code=404,
            detail="Target API key configuration tracking record not found.",
        )

    db_manager.deactivate_key(payload.old_api_key)

    token_seed = secrets.token_urlsafe(24)
    new_generated_key = f"sk_live_{token_seed}"

    db_manager.create_api_key(
        api_key=new_generated_key,
        owner=old_key_metadata["owner"],
        requests_limit=old_key_metadata["requests_limit"],
        window_size=old_key_metadata["window_size_seconds"],
    )

    return {
        "api_key": new_generated_key,
        "owner": old_key_metadata["owner"],
        "requests_limit": old_key_metadata["requests_limit"],
        "window_size_seconds": old_key_metadata["window_size_seconds"],
        "is_active": True,
        "created_at": datetime.datetime.utcnow().isoformat(),
    }
