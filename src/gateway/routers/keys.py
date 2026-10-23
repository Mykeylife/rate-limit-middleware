"""
Administrative API Key Lifecycle Management Router.

Provides secure orchestration operations to generate, inspect, and rotate
API key quotas and tracking tokens within the secure gateway perimeter.
"""

import secrets
from typing import List
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends
from gateway.database import db_manager

router = APIRouter(prefix="/api/v1/keys", tags=["API Key Administration"])


class KeyCreateRequest(BaseModel):
    """Data blueprint definition specifying parameters required to provision an API key token."""

    owner: str = Field(..., min_length=2, max_length=50, description="The identification name of the target consumer.")
    requests_limit: int = Field(5, ge=1, description="Maximum rolling transactions permitted within the target window.")
    window_size_seconds: int = Field(10, ge=1, description="Sliding window size measurement tracking configurations.")


class KeyStatusResponse(BaseModel):
    """Structural layout reporting configured parameters and active state flags of a unique token."""

    api_key: str
    owner: str
    requests_limit: int
    window_size_seconds: int
    is_active: bool
    created_at: str


class KeyRotationRequest(BaseModel):
    """Request contract providing target key token sequences marked for rotation."""

    old_api_key: str = Field(..., description="The compromised or expiring token key sequence.")


@router.post("/create", response_model=KeyStatusResponse, status_code=201)
async def generate_new_api_key(payload: KeyCreateRequest):
    """Provision a cryptographically random secure API token and commit configuration schemas to disk."""
    # Generate an unguessable prefix-bound secure client API key token sequence
    token_seed = secrets.token_urlsafe(24)
    generated_key = f"sk_live_{token_seed}"

    success = db_manager.create_api_key(
        api_key=generated_key,
        owner=payload.owner,
        requests_limit=payload.requests_limit,
        window_size=payload.window_size_seconds
    )

    if not success:
        raise HTTPException(status_code=500, detail="Database constraints prevented secure token allocation.")

    # Retrieve record snapshot for structural schema response conversions
    record = db_manager.fetch_key_status(generated_key)
    import datetime
    return {
        "api_key": generated_key,
        "owner": payload.owner,
        "requests_limit": payload.requests_limit,
        "window_size_seconds": payload.window_size_seconds,
        "is_active": True,
        "created_at": datetime.datetime.utcnow().isoformat()
    }


@router.get("/list", response_model=List[KeyStatusResponse])
async def list_managed_gateway_keys():
    """Retrieve runtime state records for all registered system API tracking tokens."""
    records = db_manager.fetch_all_keys()
    response_list = []
    for r in records:
        response_list.append({
            "api_key": r["api_key"],
            "owner": r["owner"],
            "requests_limit": r["requests_limit"],
            "window_size_seconds": r["window_size_seconds"],
            "is_active": bool(r["is_active"]),
            "created_at": str(r["created_at"])
        })
    return response_list


@router.post("/rotate", response_model=KeyStatusResponse)
async def rotate_active_api_key(payload: KeyRotationRequest):
    """Deactivate an existing API tracking key token and replace it with a fresh secure token."""
    old_key_metadata = db_manager.fetch_key_status(payload.old_api_key)
    if not old_key_metadata:
        raise HTTPException(status_code=404, detail="Target API key configuration tracking record not found.")

    # 1. Terminate structural eligibility flags on the expiring token
    db_manager.deactivate_key(payload.old_api_key)

    # 2. Re-provision exact client schema matching configuration into a fresh replacement token
    token_seed = secrets.token_urlsafe(24)
    new_generated_key = f"sk_live_{token_seed}"

    db_manager.create_api_key(
        api_key=new_generated_key,
        owner=old_key_metadata["owner"],
        requests_limit=old_key_metadata["requests_limit"],
        window_size=old_key_metadata["window_size_seconds"]
    )

    import datetime
    return {
        "api_key": new_generated_key,
        "owner": old_key_metadata["owner"],
        "requests_limit": old_key_metadata["requests_limit"],
        "window_size_seconds": old_key_metadata["window_size_seconds"],
        "is_active": True,
        "created_at": datetime.datetime.utcnow().isoformat()
    }
