from pydantic import BaseModel, Field, EmailStr
from typing import Optional

# Pydantic models for request/response validation
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class GrantRequest(BaseModel):
    grant_type: str
    client_id: str = Field(min_length=1)
    client_secret: str = Field(min_length=1)
    scope: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class TemporaryPasswordChange(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    temporary_password: str
    new_password: str = Field(min_length=8)

class AccessTokenCookie(BaseModel):
    key: str = "access_token"
    value: Optional[str] = None
    max_age: int = 300 # 60 * 5
    expires: int = 300 # 60 * 5
    path: str = "/"
    secure: bool = True
    httponly: bool = True
    samesite: str = "strict"
    domain: str = "localhost"

class RefreshTokenCookie(AccessTokenCookie):
    key: str = "refresh_token"
    max_age: int = 1800 # 60 * 30
    expires: int = 1800 # 60 * 30