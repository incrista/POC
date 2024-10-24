from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import httpx
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, List
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

class KeycloakConfig:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        server_url: str,
        realm: str,
        open_routes: Optional[List[str]] = None
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.server_url = server_url.rstrip('/')
        self.realm = realm
        self.open_routes = open_routes or [
            "/health",
            "/metrics",
            "/login",
            "/docs",
            "/openapi.json",
            "/redoc"
        ]
        
        # Construct URLs
        base_url = f"{self.server_url}/auth/realms/{realm}/protocol/openid-connect"
        self.introspect_url = f"{base_url}/token/introspect"
        self.token_url = f"{base_url}/token"

class KeycloakMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        config: KeycloakConfig,
        token_expiry_threshold: int = 300
    ):
        super().__init__(app)
        self.config = config
        self.token_expiry_threshold = token_expiry_threshold
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    async def dispatch(self, request: Request, call_next):
        start_time = datetime.utcnow()
        
        try:

            if any(request.url.path.startswith(route) for route in self.config.open_routes):
                return await call_next(request)

            access_token = self._extract_token(request)
            refresh_token = request.headers.get("X-Refresh-Token")

            token_info = await self._introspect_token(access_token)
            request.state.user = UserContext(token_info)

            if self._is_token_expiring(token_info.get("exp")):
                if refresh_token:
                    new_token, new_refresh = await self._refresh_access_token(refresh_token)
                    response = await call_next(request)
                    response.headers.update({
                        "X-New-Access-Token": new_token,
                        "Access-Control-Expose-Headers": "X-New-Access-Token, X-New-Refresh-Token"
                    })
                    if new_refresh:
                        response.headers["X-New-Refresh-Token"] = new_refresh
                    return response
                else:
                    raise AuthenticationError(
                        code=AuthErrorCode.TOKEN_EXPIRED,
                        detail="Token expired and no refresh token provided"
                    )

            return await call_next(request)

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            raise AuthenticationError(
                code=AuthErrorCode.SERVER_ERROR,
                detail="Internal authentication error"
            )
        finally:
            duration = (datetime.utcnow() - start_time).total_seconds()
            self._log_request_metrics(request, duration)

    def _extract_token(self, request: Request) -> str:
        """Extract and validate the bearer token from the request headers."""
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise AuthenticationError(
                code=AuthErrorCode.MISSING_TOKEN,
                detail="Authorization header missing or invalid"
            )
            """ raise HTTPException(
                code=AuthErrorCode.MISSING_TOKEN,
                detail="Authorization header missing or invalid"
            ) """
        return auth_header.split(" ")[1]

    async def _introspect_token(self, token: str) -> Dict:
        """Introspect the token with Keycloak server."""
        try:
            payload = {
                "token": token,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
            
            async with self.client as client:
                response = await client.post(
                    self.config.introspect_url,
                    data=payload
                )
                
            if response.status_code != 200:
                raise AuthenticationError(
                    code=AuthErrorCode.INTROSPECTION_FAILED,
                    detail="Failed to introspect token"
                )

            token_info = response.json()
            if not token_info.get("active", False):
                raise AuthenticationError(
                    code=AuthErrorCode.INVALID_TOKEN,
                    detail="Token is inactive or expired"
                )

            self._validate_token_claims(token_info)
            return token_info
            
        except httpx.RequestError as e:
            logger.error(f"Token introspection request failed: {str(e)}")
            raise AuthenticationError(
                code=AuthErrorCode.INTROSPECTION_FAILED,
                detail="Failed to connect to authentication server"
            )

    def _validate_token_claims(self, token_info: Dict) -> None:
        """Validate required token claims."""
        required_claims = ["sub", "exp", "iat", "application-roles"]
        missing_claims = [claim for claim in required_claims if claim not in token_info]
        
        if missing_claims:
            raise AuthenticationError(
                code=AuthErrorCode.INVALID_TOKEN,
                detail=f"Token missing required claims: {', '.join(missing_claims)}"
            )

    def _is_token_expiring(self, exp_timestamp: Optional[int]) -> bool:
        """Check if the token is expiring soon."""
        if not exp_timestamp:
            return True
            
        expiration_time = datetime.utcfromtimestamp(exp_timestamp)
        current_time = datetime.utcnow()
        return (expiration_time - current_time) < timedelta(seconds=self.token_expiry_threshold)

    async def _refresh_access_token(self, refresh_token: str) -> Tuple[str, Optional[str]]:
        """Refresh the access token."""
        try:
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
            
            async with self.client as client:
                response = await client.post(
                    self.config.token_url,
                    data=payload
                )
                
            if response.status_code != 200:
                raise AuthenticationError(
                    code=AuthErrorCode.REFRESH_FAILED,
                    detail="Failed to refresh access token"
                )

            token_data = response.json()
            access_token = token_data.get("access_token")
            new_refresh_token = token_data.get("refresh_token")

            if not access_token:
                raise AuthenticationError(
                    code=AuthErrorCode.REFRESH_FAILED,
                    detail="Failed to obtain new access token"
                )

            return access_token, new_refresh_token
            
        except httpx.RequestError as e:
            logger.error(f"Token refresh request failed: {str(e)}")
            raise AuthenticationError(
                code=AuthErrorCode.REFRESH_FAILED,
                detail="Failed to connect to authentication server"
            )

    def _log_request_metrics(self, request: Request, duration: float):
        """Log request metrics for monitoring."""
        logger.info(
            "Auth request metrics",
            extra={
                "path": request.url.path,
                "method": request.method,
                "duration": duration,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("User-Agent")
            }
        )

    async def __call__(self, scope, receive, send):
        """Cleanup method to close the HTTP client when the middleware is done."""
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.client.aclose()