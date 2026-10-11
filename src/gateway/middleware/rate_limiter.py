"""
Rate Limiter Middleware for FastAPI.

Implements a sliding window rate limiting algorithm to track and enforce
request quotas per API key. Intercepts every request, validates the
X-API-Key header, and returns HTTP 429 if the quota is exceeded.

Thread-safe using thread locks for in-memory state management.
"""

import time
import threading
from typing import Dict, Optional
from collections import deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


# Simulated database of valid API keys
# In production, this would be fetched from a persistent store (Redis, PostgreSQL, etc.)
VALID_API_KEYS: Dict[str, dict] = {
    "sk-test-001": {"name": "Test Client 1", "active": True},
    "sk-test-002": {"name": "Test Client 2", "active": True},
    "sk-prod-001": {"name": "Production Client", "active": True},
}


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Rate limiter middleware using a sliding window algorithm.

    Tracks request timestamps per API key within a rolling time window.
    If a client exceeds the configured request limit within the window,
    a 429 Too Many Requests response is returned.

    Attributes:
        requests_limit (int): Maximum number of requests allowed per window.
        window_size_seconds (int): Time window in seconds for rate limit calculation.
    """

    def __init__(
        self,
        app,
        requests_limit: int = 5,
        window_size_seconds: int = 10,
    ):
        """
        Initialize the Rate Limiter Middleware.

        Args:
            app: The FastAPI/Starlette application instance.
            requests_limit: Max requests allowed within the time window. Defaults to 5.
            window_size_seconds: Duration of the sliding window in seconds. Defaults to 10.
        """
        super().__init__(app)
        self.requests_limit = requests_limit
        self.window_size_seconds = window_size_seconds

        # Sliding window storage: maps API key to deque of request timestamps
        self.request_windows: Dict[str, deque] = {}

        # Thread lock for thread-safe access to request_windows
        self.lock = threading.RLock()

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """
        Extract the X-API-Key header from a request.

        Args:
            request: The incoming HTTP request.

        Returns:
            The API key string if present; None otherwise.
        """
        api_key = request.headers.get("X-API-Key")
        return api_key if api_key else None

    def _validate_api_key(self, api_key: str) -> bool:
        """
        Validate if an API key exists and is active.

        Args:
            api_key: The API key to validate.

        Returns:
            True if the API key is valid and active; False otherwise.
        """
        key_data = VALID_API_KEYS.get(api_key)
        if key_data is None:
            return False
        return bool(key_data.get("active", False))

    def _get_or_create_window(self, api_key: str) -> deque:
        """
        Get or create a sliding window deque for an API key.

        Args:
            api_key: The API key identifier.

        Returns:
            A deque containing request timestamps for the API key.
        """
        if api_key not in self.request_windows:
            self.request_windows[api_key] = deque()
        return self.request_windows[api_key]

    def _is_within_rate_limit(self, api_key: str) -> bool:
        """
        Check if a request is within the rate limit for a given API key.

        Uses a sliding window approach:
        1. Remove timestamps older than the window from the deque.
        2. Check if the current request count is below the limit.
        3. Add the current timestamp if within limit.

        Args:
            api_key: The API key to check.

        Returns:
            True if the request is within rate limit; False otherwise.
        """
        current_time = time.time()
        window_start = current_time - self.window_size_seconds

        window = self._get_or_create_window(api_key)

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
        """
        Create a standardized error JSON response.

        Args:
            status_code: HTTP status code.
            error: Error type/title.
            message: Detailed error explanation.

        Returns:
            A JSONResponse with the error payload.
        """
        return JSONResponse(
            status_code=status_code,
            content={
                "error": error,
                "message": message,
            },
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process an incoming request through the rate limiter.

        Flow:
        1. Extract X-API-Key header.
        2. Return 400 if header is missing.
        3. Validate API key against simulated database.
        4. Return 401 if API key is invalid or inactive.
        5. Check rate limit (sliding window).
        6. Return 429 if rate limit exceeded.
        7. Allow request to proceed if all checks pass.

        Args:
            request: The incoming HTTP request.
            call_next: Callable to pass the request to the next middleware/handler.

        Returns:
            A Response from the next handler, or an error response if validation fails.
        """
        # Extract API key from header
        api_key = self._extract_api_key(request)

        if not api_key:
            return self._create_error_response(
                status_code=400,
                error="Missing API key",
                message="The X-API-Key header is required.",
            )

        # Validate API key
        if not self._validate_api_key(api_key):
            return self._create_error_response(
                status_code=401,
                error="Unauthorized",
                message="The provided API key is invalid or inactive.",
            )

        # Check rate limit (thread-safe)
        with self.lock:
            within_limit = self._is_within_rate_limit(api_key)

        if not within_limit:
            return self._create_error_response(
                status_code=429,
                error="Too Many Requests",
                message=f"Rate limit exceeded. Maximum {self.requests_limit} requests per {self.window_size_seconds} seconds.",
            )

        # Request is valid; pass to next handler
        response = await call_next(request)
        return response
