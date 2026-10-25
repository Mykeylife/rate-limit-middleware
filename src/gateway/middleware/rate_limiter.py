"""Rate Limiter and Security Gateway Middleware for FastAPI.

Implements a sliding window rate limiting algorithm to enforce request quotas
per API key, injects industry-standard security headers into responses,
and performs proactive request layout structural validation checks.

Thread-safe using thread locks for in-memory state management.
"""

import threading
import time
from collections import deque
from typing import Dict, Optional

from fastapi import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class RateLimiterMiddleware:
    """ASGI Middleware integrating rate limiting and automated security gates.

    Tracks request counts using a sliding window per authenticated token,
    validates headers against malformed variants, and ensures secure,
    hardened client communication vectors via injected security headers.
    """

    def __init__(
        self,
        app: ASGIApp,
        requests_limit: int = 5,
        window_size_seconds: int = 10,
    ) -> None:
        """Initialize the Rate Limiter and Security Middleware."""
        self.app: ASGIApp = app
        self.requests_limit: int = requests_limit
        self.window_size_seconds: int = window_size_seconds

        # Sliding window storage: maps API key to deque of float timestamps
        self.request_windows: Dict[str, deque[float]] = {}

        # Thread lock for thread-safe access to request_windows
        self.lock: threading.RLock = threading.RLock()

        # Define common secure communication layer headers
        self.security_headers: Dict[str, str] = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": (
                "max-age=63072000; includeSubDomains; preload"
            ),
            "Content-Security-Policy": (
                "default-src 'self'; frame-ancestors 'none';"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
        }

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract the X-API-Key header from a request."""
        api_key: Optional[str] = request.headers.get("X-API-Key")
        return api_key

    def _validate_api_key(self, api_key: str) -> bool:
        """Validate if an API key exists and is active using SQLite."""
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

        while window and window[0] < window_start:
            window.popleft()

        if len(window) >= self.requests_limit:
            return False

        window.append(current_time)
        return True

    def _create_error_response(
        self, status_code: int, error: str, message: str
    ) -> JSONResponse:
        """Create a standardized error JSON response with hardening headers."""
        return JSONResponse(
            status_code=status_code,
            content={
                "error": error,
                "message": message,
            },
            headers=self.security_headers,
        )

    def _run_security_verification_checks(
        self, request: Request
    ) -> Optional[JSONResponse]:
        """Execute automated structure verification rules on incoming streams.

        Returns an explicit error response if constraints fail, otherwise None.
        """
        # 1. Block client requests carrying dangerously large content fields
        content_length_str = request.headers.get("content-length")
        if content_length_str:
            try:
                if int(content_length_str) > 10 * 1024 * 1024:  # 10MB Limit
                    return self._create_error_response(
                        status_code=413,
                        error="Payload Too Large",
                        message="Request content length limits exceeded.",
                    )
            except ValueError:
                return self._create_error_response(
                    status_code=400,
                    error="Bad Request",
                    message="Malformed Content-Length configuration format.",
                )

        # 2. Block mutating operations providing content type claims missing
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if not content_type:
                return self._create_error_response(
                    status_code=415,
                    error="Unsupported Media Type",
                    message="The Content-Type header must be declared.",
                )

        return None

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Process an incoming request through security verification gates."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        # Intercept infrastructure health probes directly without auth
        if request.url.path == "/healthz":

            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    for key, val in self.security_headers.items():
                        message["headers"].append(
                            (key.lower().encode(), val.encode())
                        )
                await send(message)

            await self.app(scope, receive, send_with_headers)
            return

        # Execute architectural baseline structure verification checks
        verification_error = self._run_security_verification_checks(request)
        if verification_error:
            await verification_error(scope, receive, send)
            return

        # Extract and check API Key strings
        api_key: Optional[str] = self._extract_api_key(request)

        if not api_key:
            response = self._create_error_response(
                status_code=400,
                error="Missing API key",
                message="The X-API-Key header is required.",
            )
            await response(scope, receive, send)
            return

        try:
            is_valid = self._validate_api_key(api_key)
        except Exception as exc:
            response = self._create_error_response(
                status_code=500,
                error="Internal Server Error",
                message=str(exc),
            )
            await response(scope, receive, send)
            return

        if not is_valid:
            response = self._create_error_response(
                status_code=401,
                error="Unauthorized",
                message="The provided API key is invalid or inactive.",
            )
            await response(scope, receive, send)
            return

        # Enforce rolling thread-safe rate limitation windows
        with self.lock:
            within_limit: bool = self._is_within_rate_limit(api_key)

        if not within_limit:
            response = self._create_error_response(
                status_code=429,
                error="Too Many Requests",
                message=(
                    f"Rate limit exceeded. Maximum {self.requests_limit} "
                    f"requests per {self.window_size_seconds} seconds."
                ),
            )
            await response(scope, receive, send)
            return

        # Inject security headers into successful application responses
        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                for key, val in self.security_headers.items():
                    message["headers"].append(
                        (key.lower().encode(), val.encode())
                    )
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
