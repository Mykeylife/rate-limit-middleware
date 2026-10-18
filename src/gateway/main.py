"""
FastAPI Application Entry Point with Rate Limiter Middleware Integration.

This module initializes a FastAPI application, configures the rate limiter
middleware, and provides endpoints for API key management including revocation.

All endpoints require a valid X-API-Key header and are subject to rate limiting
constraints (5 requests per 10 seconds).
"""

import logging
import os
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from gateway.middleware.rate_limiter import RateLimiterMiddleware

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
# FastAPI Application Factory
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

    # Initialize the local persistent SQLite tables layout on system boot cleanly
    from gateway.database import db_manager
    db_manager.bootstrap_tables()

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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handle request payload validation errors globally.

    Converts raw internal validation trace parameters into our standardized
    ErrorResponse data architecture format cleanly.
    """
    logger.warning(
        f"Validation failure intercepted: {str(exc.errors())}",
        extra={"path": request.url.path, "method": request.method},
    )

    error_messages = []
    for error in exc.errors():
        loc = " -> ".join(str(x) for x in error.get("loc", []))
        msg = error.get("msg", "Invalid value")
        error_messages.append(f"[{loc}]: {msg}")

    combined_message = "; ".join(error_messages)

    return JSONResponse(
        status_code=400,
        content={
            "error": "Bad Request",
            "message": f"Payload schema validation failed: {combined_message}",
            "status_code": 400,
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTPException globally."""
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
    """Handle unexpected exceptions globally."""
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
# Administrative UI Routes
# ============================================================================


@app.get("/dashboard", response_class=HTMLResponse, tags=["Admin UI"])
async def render_admin_dashboard() -> HTMLResponse:
    """
    Renders the interactive administrative control panel portal natively.

    Reads the static dashboard layout file configuration schema directly from 
    the templates folder structure workspace cleanly.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "templates", "dashboard.html")

    try:
        with open(template_path, "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content, status_code=200)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Dashboard template assets missing from gateway layout compilation tree."
        )


# ============================================================================
# Endpoints
# ============================================================================


@app.get("/healthz", status_code=200, tags=["Infrastructure"])
async def infrastructure_health_probe() -> dict:
    """
    Unauthenticated infrastructure health probe endpoint.
    Bypasses the RateLimiterMiddleware to allow automated status checks.
    """
    return {"status": "ok"}


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    status_code=200,
    tags=["Health"],
)
async def health_check() -> HealthResponse:
    """Health check endpoint (no rate limiting required)."""
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
    """Revoke (deactivate) an active API key inside the SQLite layer."""
    requester_key: Optional[str] = request.headers.get("X-API-Key")
    target_key: str = payload.api_key

    # Validate and mark the database target API key as inactive using atomic transactions
    from gateway.database import db_manager
    success = db_manager.deactivate_key(target_key)

    if not success:
        logger.warning(
            f"Attempted to revoke non-existent API key: {target_key}",
            extra={"requester": requester_key},
        )
        raise HTTPException(
            status_code=404,
            detail=f"API key '{target_key}' not found.",
        )

    logger.info(
        f"API key revoked successfully via SQLite: {target_key}",
        extra={"requester": requester_key},
    )
    return RevokeKeyResponse(
        success=True,
        message=f"API key '{target_key}' has been successfully revoked.",
        api_key=target_key,
    )
