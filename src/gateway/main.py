"""
FastAPI Application Entry Point with Rate Limiter Middleware Integration.

This module initializes a FastAPI application, configures the rate limiter
middleware, and provides endpoints for API key management including revocation.

All endpoints require a valid X-API-Key header and are subject to rate limiting
constraints (5 requests per 10 seconds).
"""

import logging
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# FIX: Corrected import path from 'xrc' to 'src' to map packages correctly
from src.gateway.middleware.rate_limiter import RateLimiterMiddleware, VALID_API_KEYS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ============================================================================
# Pydantic Request/Response Models
# ============================================================================


class RevokeKeyRequest(BaseModel):
    """
    Request payload for the key revocation endpoint.

    Attributes:
        api_key: The API key to revoke/deactivate.
    """

    api_key: str = Field(
        ..., 
        min_length=1, 
        description="The API key to revoke.",
        example="sk-test-001"
    )


class RevokeKeyResponse(BaseModel):
    """
    Response payload for successful key revocation.

    Attributes:
        success: Whether the revocation was successful.
        message: Human-readable status message.
        api_key: The API key that was revoked.
    """

    success: bool = Field(description="Revocation success status.")
    message: str = Field(description="Status message.")
    api_key: str = Field(description="The revoked API key.")


class ErrorResponse(BaseModel):
    """
    Standardized error response payload.

    Attributes:
        error: Error type or code.
        message: Detailed error message.
        status_code: HTTP status code.
    """

    error: str = Field(description="Error type or title.")
    message: str = Field(description="Detailed error explanation.")
    status_code: int = Field(description="HTTP status code.")


class HealthResponse(BaseModel):
    """
    Response payload for the health check endpoint.

    Attributes:
        status: Service status indicator.
        message: Health check message.
    """

    status: str = Field(description="Health status.", example="healthy")
    message: str = Field(description="Health check message.")


# ============================================================================
# FastAPI Application
# ============================================================================


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Sets up:
    - Rate limiter middleware (5 requests / 10 seconds per API key)
    - Global exception handlers
    - API endpoints

    Returns:
        A configured FastAPI application instance.
    """
    app_instance = FastAPI(
        title="Rate Limiter & Security Gateway",
        description="Lightweight API gateway with rate limiting and API key management.",
        version="1.0.0",
    )

    # Add rate limiter middleware
    app_instance.add_middleware(
        RateLimiterMiddleware,
        requests_limit=5,
        window_size_seconds=10,
    )

    return app_instance


# Create the application instance
app: FastAPI = create_app()


# ============================================================================
# Exception Handlers
# ============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Handle HTTPException globally.

    Args:
        request: The incoming HTTP request.
        exc: The HTTPException raised.

    Returns:
        A JSONResponse with error details.
    """
    logger.warning(
        f"HTTPException raised: {exc.status_code} - {exc.detail}",
        extra={"path": request.url.path, "method": request.method},
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Exception",
            "message": str(exc.detail),
            "status_code": exc.status_code,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions globally.

    Args:
        request: The incoming HTTP request.
        exc: The exception raised.

    Returns:
        A JSONResponse with a generic error message.
    """
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)}",
        extra={"path": request.url.path, "method": request.method},
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred. Please try again later.",
            "status_code": 500,
        },
    )


# ============================================================================
# Endpoints
# ============================================================================


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    status_code=200,
    tags=["Health"],
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint (no rate limiting required).

    Returns:
        A HealthResponse indicating the service is operational.
    """
    logger.info("Health check endpoint accessed.")
    return HealthResponse(
        status="healthy",
        message="The rate limiter gateway is operational.",
    )


@app.post(
    "/api/v1/keys/revoke",
    response_model=RevokeKeyResponse,
    status_code=200,
    tags=["Key Management"],
    responses={
        400: {"model": ErrorResponse, "description": "Missing or invalid payload."},
        401: {"model": ErrorResponse, "description": "Unauthorized (invalid API key)."},
        404: {"model": ErrorResponse, "description": "API key not found."},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded."},
        500: {"model": ErrorResponse, "description": "Internal server error."},
    },
)
async def revoke_api_key(
    request: Request, 
    payload: RevokeKeyRequest
) -> RevokeKeyResponse:
    """
    Revoke (deactivate) an active API key.

    This endpoint requires a valid X-API-Key header and is subject to
    rate limiting. The API key to revoke is provided in the request body.

    Args:
        request: The incoming HTTP request.
        payload: The request body containing the API key to revoke.

    Returns:
        A RevokeKeyResponse with revocation status.

    Raises:
        HTTPException: If the API key to revoke is not found.
    """
    # Extract the X-API-Key header for logging/audit
    requester_key: Optional[str] = request.headers.get("X-API-Key")
    target_key: str = payload.api_key

    # Validate that the target API key exists
    if target_key not in VALID_API_KEYS:
        logger.warning(
            f"Attempted to revoke non-existent API key: {target_key}",
            extra={"requester": requester_key},
        )
        raise HTTPException(
            status_code=404,
            detail=f"API key '{target_key}' not found.",
        )

    # Mark the API key as inactive
    try:
        VALID_API_KEYS[target_key]["active"] = False
        logger.info(
            f"API key revoked successfully: {target_key}",
            extra={"requester": requester_key},
        )
        return RevokeKeyResponse(
            success=True,
            message=f"API key '{target_key}' has been successfully revoked.",
            api_key=target_key,
        )
    except KeyError as e:
        logger.error(
            f"KeyError while revoking API key: {str(e)}",
            extra={"requester": requester_key, "target_key": target_key},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail="An error occurred while revoking the API key.",
        )
