"""Utility functions for Willow SDK."""

import asyncio
import uuid
import time
from typing import TypeVar, Callable, Optional, Awaitable
from functools import wraps
from .errors import NotAuthenticatedError


def generate_id(prefix: Optional[str] = None) -> str:
    """Generate a unique ID.

    Args:
        prefix: Optional prefix for the ID

    Returns:
        Generated ID string
    """
    unique_id = uuid.uuid4().hex[:12]
    return f"{prefix}_{unique_id}" if prefix else unique_id


async def sleep(ms: int) -> None:
    """Sleep for specified milliseconds.

    Args:
        ms: Milliseconds to sleep
    """
    await asyncio.sleep(ms / 1000)


T = TypeVar('T')


async def retry(
    func: Callable[[], Awaitable[T]],
    max_attempts: int = 3,
    delay: int = 1000,
    backoff: bool = True
) -> T:
    """Retry an async function with exponential backoff.

    Args:
        func: Async function to retry
        max_attempts: Maximum number of attempts
        delay: Initial delay in milliseconds
        backoff: Whether to use exponential backoff

    Returns:
        Result from successful function call

    Raises:
        Last exception if all attempts fail
    """
    last_error: Optional[Exception] = None
    current_delay = delay

    for attempt in range(max_attempts):
        try:
            return await func()
        except Exception as e:
            last_error = e
            if attempt < max_attempts - 1:
                await sleep(current_delay)
                if backoff:
                    current_delay *= 2

    if last_error is not None:
        raise last_error
    raise RuntimeError("Retry failed with no error captured")


def require_auth(method):
    """Decorator to require authentication for a method.

    Checks if the client has an active session before allowing the method to run.

    Raises:
        NotAuthenticatedError: If the client is not authenticated
    """
    @wraps(method)
    async def wrapper(self, *args, **kwargs):
        if not hasattr(self, 'client') or not self.client.is_authenticated():
            raise NotAuthenticatedError()
        return await method(self, *args, **kwargs)
    return wrapper


def validate_did(did: str) -> bool:
    """Validate DID format.

    Args:
        did: DID string to validate

    Returns:
        True if valid, False otherwise
    """
    if not did.startswith("did:willow:"):
        return False
    parts = did.split(":")
    return len(parts) >= 4


def validate_hex_string(hex_str: str, expected_length: Optional[int] = None) -> bool:
    """Validate hex string format.

    Args:
        hex_str: Hex string to validate
        expected_length: Expected length in bytes (not hex chars)

    Returns:
        True if valid, False otherwise
    """
    try:
        bytes_data = bytes.fromhex(hex_str)
        if expected_length is not None:
            return len(bytes_data) == expected_length
        return True
    except ValueError:
        return False


def calculate_backoff(attempt: int, initial_delay_ms: int = 100, max_delay_ms: int = 10000, exponential_base: float = 2.0) -> int:
    """Calculate exponential backoff delay.

    Args:
        attempt: Current attempt number (0-indexed)
        initial_delay_ms: Initial delay in milliseconds
        max_delay_ms: Maximum delay in milliseconds
        exponential_base: Base for exponential calculation

    Returns:
        Delay in milliseconds
    """
    delay = initial_delay_ms * (exponential_base ** attempt)
    return min(int(delay), max_delay_ms)


class RateLimiter:
    """Simple rate limiter for API calls.

    Example:
        ```python
        limiter = RateLimiter(max_calls=10, time_window=1.0)
        for _ in range(20):
            await limiter.acquire()
            await make_api_call()
        ```
    """

    def __init__(self, max_calls: int, time_window: float):
        """Initialize rate limiter.

        Args:
            max_calls: Maximum number of calls allowed in the time window
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls: list[float] = []

    async def acquire(self):
        """Wait if necessary to respect rate limit."""
        now = time.time()
        # Remove old calls outside the time window
        self.calls = [t for t in self.calls if now - t < self.time_window]

        if len(self.calls) >= self.max_calls:
            # Wait until the oldest call is outside the window
            sleep_time = self.time_window - (now - self.calls[0]) + 0.1
            await asyncio.sleep(sleep_time)
            await self.acquire()  # Retry
        else:
            self.calls.append(now)

    def reset(self):
        """Reset the rate limiter."""
        self.calls = []
