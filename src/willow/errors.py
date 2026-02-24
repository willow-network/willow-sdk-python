"""Error types for Willow SDK.

This module provides a comprehensive error hierarchy for handling various
error conditions when interacting with the Willow API.
"""

from typing import Optional, Any


class WillowError(Exception):
    """Base exception for Willow SDK errors.

    All SDK errors inherit from this class, making it easy to catch
    any Willow-related error with a single except clause.

    Attributes:
        message: Human-readable error message
        status_code: HTTP status code if applicable
        details: Additional error details
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        details: Optional[Any] = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details

    def __str__(self) -> str:
        parts = [self.message]
        if self.status_code:
            parts.append(f"(Status: {self.status_code})")
        if self.details:
            parts.append(f"Details: {self.details}")
        return " ".join(parts)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r}, status_code={self.status_code}, details={self.details!r})"


class NetworkError(WillowError):
    """Network communication errors.

    Raised when network-level issues occur, such as connection failures,
    timeouts, or DNS resolution errors.
    """
    pass


class HttpError(WillowError):
    """HTTP-level errors with status code.

    Raised when the server returns an HTTP error response.
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        details: Optional[Any] = None
    ):
        super().__init__(message, status_code, details)


class AuthenticationError(WillowError):
    """Authentication-related errors.

    Raised when authentication fails, such as invalid credentials,
    expired sessions, or missing authentication.
    """
    pass


class NotAuthenticatedError(AuthenticationError):
    """Error raised when authentication is required but not present.

    This is a specific authentication error for cases where no
    authentication was provided at all.
    """

    def __init__(self, message: str = "Not authenticated. Please call set_identity() first."):
        super().__init__(message, status_code=401)


class ValidationError(WillowError):
    """Validation errors for request data.

    Raised when input data fails validation, such as missing required
    fields or invalid field values.
    """

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, status_code=400, details=details)


class NotFoundError(WillowError):
    """Resource not found errors.

    Raised when a requested resource (DID, app, subgrove, data, etc.)
    does not exist.
    """

    def __init__(self, message: str = "Resource not found", details: Optional[Any] = None):
        super().__init__(message, status_code=404, details=details)


class PermissionDeniedError(WillowError):
    """Permission denied errors.

    Raised when the authenticated user does not have permission
    to perform the requested operation.
    """

    def __init__(self, message: str = "Permission denied", details: Optional[Any] = None):
        super().__init__(message, status_code=403, details=details)


class ProofVerificationError(WillowError):
    """Proof verification errors.

    Raised when cryptographic proof verification fails. This could
    indicate data tampering or an invalid proof.
    """
    pass


class LightClientError(WillowError):
    """Light client errors.

    Raised when light client operations fail, such as header
    verification or sync issues.
    """
    pass


class CryptoError(WillowError):
    """Cryptographic operation errors.

    Raised when cryptographic operations fail, such as key generation,
    signing, or signature verification.
    """
    pass


class InvalidSignatureError(CryptoError):
    """Invalid signature error.

    Raised when a signature is invalid or cannot be verified.
    """

    def __init__(self, message: str = "Invalid signature"):
        super().__init__(message)


class SerializationError(WillowError):
    """Serialization/deserialization errors.

    Raised when data cannot be serialized or deserialized properly.
    """
    pass


class ConfigError(WillowError):
    """Configuration errors.

    Raised when there are issues with SDK configuration, such as
    invalid URLs or missing required configuration.
    """
    pass


class TimeoutError(NetworkError):
    """Request timeout error.

    Raised when a request times out waiting for a response.
    """

    def __init__(self, message: str = "Request timed out"):
        super().__init__(message)


class RateLimitError(WillowError):
    """Rate limit exceeded error.

    Raised when the API rate limit has been exceeded.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None
    ):
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class ConsensusError(WillowError):
    """Consensus-related errors.

    Raised when consensus operations fail, such as transaction
    broadcasting or block validation.
    """
    pass


class TransactionError(ConsensusError):
    """Transaction-related errors.

    Raised when transaction operations fail.
    """

    def __init__(
        self,
        message: str,
        tx_hash: Optional[str] = None,
        error_code: Optional[int] = None,
        raw_log: Optional[str] = None
    ):
        super().__init__(message)
        self.tx_hash = tx_hash
        self.error_code = error_code
        self.raw_log = raw_log


class InsufficientFundsError(TransactionError):
    """Insufficient funds error.

    Raised when an account has insufficient balance for an operation.
    """

    def __init__(
        self,
        message: str = "Insufficient funds",
        required: Optional[int] = None,
        available: Optional[int] = None
    ):
        super().__init__(message)
        self.required = required
        self.available = available


def parse_api_error(response_data: dict, status_code: int) -> WillowError:
    """Parse API error response into appropriate WillowError subclass.

    Args:
        response_data: Response data dictionary from the API
        status_code: HTTP status code

    Returns:
        Appropriate WillowError subclass based on status code and error details
    """
    error_message = response_data.get("error", "Unknown error")
    details = response_data.get("details")

    # Map status codes to error types
    if status_code == 400:
        return ValidationError(error_message, details=details)
    elif status_code == 401:
        return AuthenticationError(error_message, status_code=status_code, details=details)
    elif status_code == 403:
        return PermissionDeniedError(error_message, details=details)
    elif status_code == 404:
        return NotFoundError(error_message, details=details)
    elif status_code == 429:
        retry_after = response_data.get("retry_after")
        return RateLimitError(error_message, retry_after=retry_after)
    elif status_code >= 500:
        return WillowError(f"Server error: {error_message}", status_code=status_code, details=details)
    else:
        return WillowError(error_message, status_code=status_code, details=details)
