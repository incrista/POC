from fastapi import Request
from starlette.types import ASGIApp, Scope, Receive, Send, Message
from starlette.responses import JSONResponse
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Set
import logging
from core.auth.models import User, KeycloakConfig
from api.errors.errors import AuthenticationError, AuthErrorCode

logger = logging.getLogger(__name__)

class KeycloakMiddleware:
    """ASGI middleware for Keycloak authentication"""
    
    # Standard auth endpoints that should be open
    AUTH_ENDPOINTS: Set[str] = {
        "/api/login",
        "/api/onboard",
        "/api/token",
        "/api/token/refresh",
        "/api/reset",
        "/api/logout"
    }
    
    def __init__(self, app: ASGIApp, config: KeycloakConfig, keycloak_openid: KeycloakOpenID):
        self.app = app
        self.config = config
        self.keycloak = keycloak_openid
        
        # Merge AUTH_ENDPOINTS with config's open endpoints
        self.open_paths = set(config.OPEN_ENDPOINTS) | self.AUTH_ENDPOINTS
        self.bypass_paths = set(config.BYPASS_ENDPOINTS)
        self.wildcard_paths = {path[:-2] for path in config.OPEN_ENDPOINTS if path.endswith("/*")}
        
        # Special handling for logout
        self.protected_with_token = {"/api/logout"}

    def is_open_path(self, path: str) -> bool:
        """Efficiently check if path is open"""
        return (path in self.open_paths or 
                path in self.bypass_paths or 
                any(path.startswith(prefix) for prefix in self.wildcard_paths))

    def needs_token_validation(self, path: str) -> bool:
        """Check if path needs token validation despite being open"""
        return path in self.protected_with_token

    async def handle_token_refresh(self, token_info: Dict, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Handle token refresh if needed"""
        exp_timestamp = token_info.get("exp")
        if not exp_timestamp:
            return None
            
        if (datetime.utcfromtimestamp(exp_timestamp) - datetime.utcnow() 
            < timedelta(seconds=self.config.TOKEN_EXPIRY_THRESHOLD)):
            try:
                token_data = await self.keycloak.refresh_token(refresh_token)
                return token_data['access_token'], token_data.get('refresh_token')
            except KeycloakError as e:
                logger.warning(f"Token refresh failed: {e}")
                return None
        return None

    async def validate_token(self, access_token: str) -> Dict:
        """Validate token and return token info"""
        try:
            token_info = await self.keycloak.introspect(access_token)
            if not token_info.get("active", False):
                raise KeycloakError("Token inactive")
            return token_info
        except KeycloakError as e:
            raise AuthenticationError(
                code=AuthErrorCode.INVALID_TOKEN,
                detail=str(e)
            )

    async def create_user_context(self, token_info: Dict) -> str:
        """Create and serialize user context"""
        return User(
            user_id=token_info.get("sub"),
            username=token_info.get("preferred_username"),
            email=token_info.get("email"),
            roles=set(token_info.get("application-roles", [])),
            exp=token_info.get("exp"),
            client_id=token_info.get("azp"),
            raw_token=token_info
        ).model_dump_json()

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        """Main middleware handler"""
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        
        # Skip middleware for non-auth open paths
        if self.is_open_path(path) and not self.needs_token_validation(path):
            await self.app(scope, receive, send)
            return

        start_time = datetime.utcnow()
        headers = dict(scope.get("headers", []))

        try:
            # Extract tokens
            auth_header = headers.get(b"authorization", b"").decode()
            if not auth_header.startswith("Bearer "):
                raise AuthenticationError(
                    code=AuthErrorCode.MISSING_TOKEN,
                    detail="Authorization header missing or invalid"
                )
            
            access_token = auth_header[7:]  # Remove "Bearer " prefix
            refresh_token = headers.get(b"x-refresh-token", b"").decode()

            # Validate token
            token_info = await self.validate_token(access_token)
            
            # Add user to scope
            scope["user"] = await self.create_user_context(token_info)

            # Handle token refresh
            if refresh_token and path != "/api/token/refresh":  # Don't refresh during refresh request
                new_tokens = await self.handle_token_refresh(token_info, refresh_token)
                if new_tokens:
                    new_access, new_refresh = new_tokens
                    async def send_wrapper(message: Message):
                        if message["type"] == "http.response.start":
                            headers = message.get("headers", [])
                            headers.extend([
                                (b"X-New-Access-Token", new_access.encode()),
                                (b"Access-Control-Expose-Headers", b"X-New-Access-Token, X-New-Refresh-Token"),
                                (b"X-New-Refresh-Token", new_refresh.encode()) if new_refresh else None
                            ])
                            message["headers"] = [h for h in headers if h is not None]
                        await send(message)
                    await self.app(scope, receive, send_wrapper)
                    return

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
            if logger.isEnabledFor(logging.INFO):
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.info(
                    "Auth request metrics",
                    extra={
                        "path": path,
                        "method": scope.get("method"),
                        "duration": duration,
                        "client_ip": scope.get("client", [None])[0],
                        "user_agent": headers.get(b"user-agent", b"").decode()
                    }
                )