from fastapi import HTTPException
from enum import Enum
from typing import Optional, Dict

class AuthErrorCode(str, Enum):
    MISSING_TOKEN = "missing_token"
    INVALID_TOKEN = "invalid_token"
    TOKEN_EXPIRED = "token_expired"
    INTROSPECTION_FAILED = "introspection_failed"
    REFRESH_FAILED = "refresh_failed"
    SERVER_ERROR = "server_error"

class AuthenticationError(HTTPException):
    def __init__(self, code: AuthErrorCode, detail: str, headers: Optional[Dict] = None):
        super().__init__(
            status_code=401,
            detail={"code": code, "message": detail},
            headers=headers
        )

class AuthorizationError(HTTPException):
    def __init__(self, code: AuthErrorCode, detail: str, headers: Optional[Dict] = None):
        super().__init__(
            status_code=401,
            detail={"code": code, "message": detail},
            headers=headers
        )
