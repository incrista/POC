from pydantic import BaseModel, Field
from typing import Optional, Set, Dict

class User(BaseModel):
    user_id: str
    username: str
    email: Optional[str]
    roles: Set[str]
    exp: Optional[int]
    client_id: Optional[str]
    disabled: bool = False
    raw_token: Dict

class KeycloakConfig(BaseModel):
    """Keycloak authentication configuration"""
    CLIENT_ID: str = Field(..., description="Keycloak client ID")
    CLIENT_SECRET: str = Field(..., description="Keycloak client secret")
    SERVER_URL: str = Field(..., description="Keycloak server URL")
    REALM: str = Field(..., description="Keycloak realm")
    ALGORITHM: str = "RS256"
    TOKEN_EXPIRY_THRESHOLD: int = 300
    OPEN_ENDPOINTS: Set[str] = {
        "/health",
        "/metrics",
        "/login",
        "/docs",
        "/openapi.json",
        "/redoc"
    }
    BYPASS_ENDPOINTS: Set[str] = {
        "/metrics",
        "/_internal/health"
    }
    introspect_url: Optional[str] = None
    token_url: Optional[str] = None

    def __init__(self, **data):
        super().__init__(**data)
        base_url = f"{self.SERVER_URL.rstrip('/')}/realms/{self.REALM}/protocol/openid-connect"
        self.introspect_url = f"{base_url}/token/introspect"
        self.token_url = f"{base_url}/token"

    class Config:
        arbitrary_types_allowed = True