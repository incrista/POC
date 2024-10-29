from fastapi import Request, HTTPException
from starlette.types import ASGIApp, Scope, Receive, Send, Message
from starlette.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, List, Set
from enum import Enum
import logging
from core.auth.service import Role, ApplicationID
from api.errors.errors import AuthenticationError, AuthErrorCode

logger = logging.getLogger(__name__)

class UserContext:
    def __init__(self, token_info: Dict):
        self.user_id = token_info.get("sub")
        self.username = token_info.get("preferred_username")
        self.email = token_info.get("email")
        self.roles = token_info.get("application-roles", [])
        self.exp = token_info.get("exp")
        self.client_id = token_info.get("azp")
        self.raw_token = token_info

    def get_application_roles(self, app_id: ApplicationID) -> List[Role]:
        app_prefix = f"/Applications/{app_id}"
        return [
            Role(role.replace(f"{app_prefix}/", ""))
            for role in self.roles
            if role.startswith(app_prefix) and any(role.endswith(r.value) for r in Role)
        ]
    
class User(BaseModel):
    user_id: str
    username: str
    email: Optional[str]
    roles: Set[str]
    exp: Optional[int]
    client_id: Optional[str]
    disabled: bool = False
    raw_token: Dict

    def get_application_roles(self, app_id: ApplicationID) -> List[Role]:
        app_prefix = f"/Applications/{app_id}"
        return [
            Role(role.replace(f"{app_prefix}/", ""))
            for role in self.roles
            if role.startswith(app_prefix) and any(role.endswith(r.value) for r in Role)
        ]

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
    introspect_url: Optional[str] = None  # Added field
    token_url: Optional[str] = None  # Added field

    def __init__(self, **data):
        super().__init__(**data)
        base_url = f"{self.SERVER_URL.rstrip('/')}/auth/realms/{self.REALM}/protocol/openid-connect"
        self.introspect_url = f"{base_url}/token/introspect"
        self.token_url = f"{base_url}/token"

    class Config:
        arbitrary_types_allowed = True

class KeycloakMiddleware:
    """ASGI middleware for Keycloak authentication"""
    def __init__(
        self,
        app: ASGIApp,
        config: KeycloakConfig,
    ):
        self.app = app
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    def is_path_open(self, path: str) -> bool:
        """Check if path matches open endpoints, including wildcards"""
        if path in self.config.OPEN_ENDPOINTS or path in self.config.BYPASS_ENDPOINTS:
            return True
        
        for open_path in self.config.OPEN_ENDPOINTS:
            if open_path.endswith("/*"):
                prefix = open_path[:-1]
                if path.startswith(prefix):
                    return True
        return False

    async def _extract_token(self, headers: Dict[bytes, bytes]) -> Tuple[str, Optional[str]]:
        """Extract access and refresh tokens from headers"""
        auth_header = headers.get(b"authorization", b"").decode()
        refresh_token = headers.get(b"x-refresh-token", b"").decode()

        if not auth_header or not auth_header.startswith("Bearer "):
            raise AuthenticationError(
                code="missing_token",
                detail="Authorization header missing or invalid"
            )

        return auth_header.replace("Bearer ", ""), refresh_token

    async def _introspect_token(self, token: str) -> Dict:
        """Introspect the token with Keycloak server"""
        try:
            payload = {
                "token": token,
                "client_id": self.config.CLIENT_ID,
                "client_secret": self.config.CLIENT_SECRET,
            }
            
            async with self.client as client:
                response = await client.post(self.config.introspect_url, data=payload)
                
            if response.status_code != 200:
                raise AuthenticationError(
                    code="introspection_failed",
                    detail="Failed to introspect token"
                )

            token_info = response.json()
            if not token_info.get("active", False):
                raise AuthenticationError(
                    code="invalid_token",
                    detail="Token is inactive or expired"
                )

            self._validate_token_claims(token_info)
            return token_info
            
        except httpx.RequestError as e:
            logger.error(f"Token introspection request failed: {str(e)}")
            raise AuthenticationError(
                code="introspection_failed",
                detail="Failed to connect to authentication server"
            )

    def _validate_token_claims(self, token_info: Dict) -> None:
        """Validate required token claims"""
        required_claims = ["sub", "exp", "iat", "application-roles"]
        missing_claims = [claim for claim in required_claims if claim not in token_info]
        
        if missing_claims:
            raise AuthenticationError(
                code="invalid_token",
                detail=f"Token missing required claims: {', '.join(missing_claims)}"
            )

    def _is_token_expiring(self, exp_timestamp: Optional[int]) -> bool:
        """Check if the token is expiring soon"""
        if not exp_timestamp:
            return True
            
        expiration_time = datetime.utcfromtimestamp(exp_timestamp)
        current_time = datetime.utcnow()
        return (expiration_time - current_time) < timedelta(seconds=self.config.TOKEN_EXPIRY_THRESHOLD)

    async def _refresh_access_token(self, refresh_token: str) -> Tuple[str, Optional[str]]:
        """Refresh the access token"""
        try:
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.config.CLIENT_ID,
                "client_secret": self.config.CLIENT_SECRET,
            }
            
            async with self.client as client:
                response = await client.post(self.config.token_url, data=payload)
                
            if response.status_code != 200:
                raise AuthenticationError(
                    code="refresh_failed",
                    detail="Failed to refresh access token"
                )

            token_data = response.json()
            access_token = token_data.get("access_token")
            new_refresh_token = token_data.get("refresh_token")

            if not access_token:
                raise AuthenticationError(
                    code="refresh_failed",
                    detail="Failed to obtain new access token"
                )

            return access_token, new_refresh_token
            
        except httpx.RequestError as e:
            logger.error(f"Token refresh request failed: {str(e)}")
            raise AuthenticationError(
                code="refresh_failed",
                detail="Failed to connect to authentication server"
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        """Main middleware handler"""
        if scope["type"] == "lifespan":
            await self.handle_lifespan(scope, receive, send)
            return
            
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        start_time = datetime.utcnow()
        path = scope.get("path", "")
        
        # Check for bypass and open endpoints first
        if path in self.config.BYPASS_ENDPOINTS:
            await self.app(scope, receive, send)
            return

        if self.is_path_open(path):
            await self.app(scope, receive, send)
            return

        try:
            headers = dict(scope.get("headers", []))
            access_token, refresh_token = await self._extract_token(headers)
            token_info = await self._introspect_token(access_token)

            # Create user context
            user = User(
                user_id=token_info.get("sub"),
                username=token_info.get("preferred_username"),
                email=token_info.get("email"),
                roles=set(token_info.get("application-roles", [])),
                exp=token_info.get("exp"),
                client_id=token_info.get("azp"),
                raw_token=token_info
            )

            # Add user to scope for use in dependencies
            scope["user"] = user

            # Handle token refresh if needed
            if self._is_token_expiring(token_info.get("exp")):
                if refresh_token:
                    new_token, new_refresh = await self._refresh_access_token(refresh_token)
                    
                    # Create a wrapper for the send function to modify headers
                    async def send_wrapper(message: Message):
                        if message["type"] == "http.response.start":
                            headers = message.get("headers", [])
                            headers.extend([
                                (b"X-New-Access-Token", new_token.encode()),
                                (b"Access-Control-Expose-Headers", b"X-New-Access-Token, X-New-Refresh-Token")
                            ])
                            if new_refresh:
                                headers.append((b"X-New-Refresh-Token", new_refresh.encode()))
                            message["headers"] = headers
                        await send(message)

                    await self.app(scope, receive, send_wrapper)
                    return
                else:
                    raise AuthenticationError(
                        code="token_expired",
                        detail="Token expired and no refresh token provided"
                    )

            await self.app(scope, receive, send)

        except AuthenticationError as e:
            response = JSONResponse(
                status_code=401,
                content={"code": e.detail["code"], "detail": e.detail["message"]},
                headers={"WWW-Authenticate": "Bearer"}
            )
            await response(scope, receive, send)
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            response = JSONResponse(
                status_code=500,
                content={"code": "server_error", "detail": "Internal authentication error"}
            )
            await response(scope, receive, send)
        finally:
            duration = (datetime.utcnow() - start_time).total_seconds()
            self._log_request_metrics(scope, duration)
            await self.client.aclose()
    
    async def handle_lifespan(self, scope: Scope, receive: Receive, send: Send):
        """Handle lifespan events"""
        try:
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    # Initialize any resources if needed
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    # Clean up resources
                    await self.client.aclose()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        except Exception as e:
            logger.error(f"Error in lifespan: {str(e)}", exc_info=True)
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.failed", "message": str(e)})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.failed", "message": str(e)})
            return

    def _log_request_metrics(self, scope: Scope, duration: float):
        """Log request metrics for monitoring"""
        client = scope.get("client", [None, None])
        headers = dict(scope.get("headers", []))
        user_agent = headers.get(b"user-agent", b"").decode()
        
        logger.info(
            "Auth request metrics",
            extra={
                "path": scope.get("path"),
                "method": scope.get("method"),
                "duration": duration,
                "client_ip": client[0],
                "user_agent": user_agent
            }
        )