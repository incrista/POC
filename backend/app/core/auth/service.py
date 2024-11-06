from fastapi import Response
from typing import Dict, List, Optional, Tuple
from enum import Enum
from api.errors.errors import AuthenticationError, AuthErrorCode
from core.auth.models import *
import logging
import httpx

logger = logging.getLogger(__name__)

class ApplicationID(str, Enum):
    APP1 = "App1"
    APP2 = "App2"
    APP3 = "App3"
    APP4 = "App4"

class Role(str, Enum):
    SUPER_ADMIN = "super-admin"
    ADMIN = "admin"
    OPERATOR = "operator"
    USER = "user"

class AuthorizationService:
    def __init__(self):
        self.role_hierarchy = {
            Role.SUPER_ADMIN: [Role.SUPER_ADMIN, Role.ADMIN, Role.OPERATOR, Role.USER],
            Role.ADMIN: [Role.ADMIN, Role.OPERATOR, Role.USER],
            Role.OPERATOR: [Role.OPERATOR, Role.USER],
            Role.USER: [Role.USER]
        }

    def get_user_role(self, user: User, app_id: ApplicationID) -> Optional[Role]:
        application_roles = user.roles
        app_prefix = f"{app_id}"
        
        for role in Role:
            if f"{app_prefix}.{role}" in application_roles:
                return role
        return None

    def has_permission(self, user_role: Role, required_role: Role) -> bool:
        if user_role not in self.role_hierarchy:
            return False
        return required_role in self.role_hierarchy[user_role]
    
async def extract_token(headers: Dict[bytes, bytes]) -> Tuple[str, Optional[str]]:
        """Extract access and refresh tokens from headers"""
        auth_header = headers.get(b"authorization", b"").decode()
        refresh_token = headers.get(b"x-refresh-token", b"").decode()

        if not auth_header or not auth_header.startswith("Bearer "):
            raise AuthenticationError(
                code=AuthErrorCode.MISSING_TOKEN,
                detail="Authorization header missing or invalid"
            )
        
        return auth_header.replace("Bearer ", ""), refresh_token

async def refresh_access_token(config: KeycloakConfig, refresh_token: str, client: httpx.AsyncClient, logger: logging.Logger) -> Tuple[str, Optional[str]]:
        """Refresh the access token"""
        try:
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": config.CLIENT_ID,
                "client_secret": config.CLIENT_SECRET,
            }
            
            response = await client.post(config.token_url, data=payload)
                
            if response.status_code != 200:
                raise AuthenticationError(
                    code=AuthErrorCode.REFRESH_FAILED,
                    detail="Failed to refresh access token"
                )

            token_data : dict = response.json()
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

def create_cookie(response: Response, cookie_config: AccessTokenCookie | RefreshTokenCookie) -> None:
    """
    Sets a cookie on the response using parameters from a Pydantic model.
    Maps the Pydantic model fields to FastAPI's Response.set_cookie() parameters.
    
    Args:
        response (Response): The FastAPI response object
        cookie_config (Union[AccessTokenCookie, RefreshTokenCookie]): Cookie configuration
    """
    try:
        # Convert model to dict and prepare cookie parameters
        cookie_params = cookie_config.model_dump(exclude_none=True)
        
        # Extract the key and value
        key = cookie_params.pop('key')
        value = cookie_params.pop('value')
        
        # Correctly map samesite parameter (FastAPI expects 'same_site')
        # if 'samesite' in cookie_params:
        #     cookie_params['same_site'] = cookie_params.pop('samesite')
            
        # Set the cookie with correct parameters
        response.set_cookie(
            key=key,
            value=value,
            **cookie_params
        )
        
        logger.debug(f"Cookie '{key}' set successfully")
        
    except Exception as e:
        logger.error(f"Failed to set cookie: {str(e)}")
        raise