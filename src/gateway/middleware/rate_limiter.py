"""
Rate Limiter Middleware for FastAPI.

Implements a sliding window rate limiting algorithm to track and enforce
request quotas per API key. Intercepts every request, validates the
X-API-Key header, and returns HTTP 429 if the quota is exceeded.

Thread-safe using thread locks for in-memory state management.
"""

import threading
import time
from collections import deque
from typing import Dict, Optional

from fastapi import Request
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse


class RateLimiterMiddleware:
    """
    Rate limiter middleware using a sliding window algorithm.

    Tracks request timestamps per API key within a rolling time window.
    If a client exceeds the configured request limit within the window,
    a 429 Too Many Requests response is returned.
    """

    def __init__(
        self,
        app: ASGIApp,
        requests_limit: int = 5,
        window_size_seconds: int = 10,
    ) -> None:
        """Initialize the Rate Limiter Middleware."""
        self.app: ASGIApp = app
        self.requests_limit: int = requests_limit
        self.window_size_seconds: int = window_size_seconds

        # Sliding window storage: maps API key to deque of float request timestamps
        self.request_windows: Dict[str, deque[float]] = {}

        # Thread lock for thread-safe access to request_windows
        self.lock: threading.RLock = threading.RLock()

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract the X-API-Key header from a request."""
        api_key: Optional[str] = request.headers.get("X-API-Key")
        return api_key

    def _validate_api_key(self, api_key: str) -> bool:
        """Validate if an API key exists and is active using SQLite persistence."""
        from gateway.database import db_manager
        key_data = db_manager.fetch_key_status(api_key)
        if key_data is None:
            return False
        return bool(key_data.get("active", False))

    def _get_or_create_window(self, api_key: str) -> deque[float]:
        """Get or create a sliding window deque for an API key."""
        if api_key not in self.request_windows:
            self.request_windows[api_key] = deque()
        return self.request_windows[api_key]

    def _is_within_rate_limit(self, api_key: str) -> bool:
        """Check if a request is within the rate limit for a given API key."""
        current_time: float = time.time()
        window_start: float = current_time - self.window_size_seconds

        window: deque[float] = self._get_or_create_window(api_key)

        # Remove expired timestamps (older than window start)
        while window and window[0] < window_start:
            window.popleft()

        # Check if within limit
        if len(window) >= self.requests_limit:
            return False

        window.append(current_time)
        return True

    def _create_error_response(
        self, status_code: int, error: str, message: str
    ) -> JSONResponse:
        """Create a standardized error JSON response."""
        return JSONResponse(
            status_code=status_code,
            content={
                "error": error,
                "message": message,
            },
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process an incoming request through the rate limiter."""
        # Only intercept standard HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        # Allow the unauthenticated infrastructure health probe to pass through directly
        if request.url.path == "/healthz":
            await self.app(scope, receive, send)
            return

        # Extract API key from header
        api_key: Optional[str] = self._extract_api_key(request)

        if not api_key:
            response = self._create_error_response(
                status_code=400,
                error="Missing API key",
                message="The X-API-Key header is required.",
            )
            await response(scope, receive, send)
            return

        # Validate API key
        if not self._validate_api_key(api_key):
            response = self._create_error_response(
                status_code=401,
                error="Unauthorized",
                message="The provided API key is invalid or inactive.",
            )
            await response(scope, receive, send)
            return

        # Check rate limit (thread-safe)
        with self.lock:
            within_limit: bool = self._is_within_rate_limit(api_key)

        if not within_limit:
            response = self._create_error_response(
                status_code=429,
                error="Too Many Requests",
                message=f"Rate limit exceeded. Maximum {self.requests_limit} requests per {self.window_size_seconds} seconds.",
            )
            await response(scope, receive, send)
            return

        # Request is valid; pass to next handler down the ASGI pipeline
        try:
            await self.app(scope, receive, send)
        except Exception as exc:
            # Captures downstream application errors cleanly without TaskGroups
            response = self._create_error_response(
                status_code=500,
                error="Internal Server Error",
                message=str(exc)
            )
            await response(scope, receive, send)
