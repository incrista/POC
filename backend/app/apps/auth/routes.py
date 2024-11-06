import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Annotated, Optional
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from keycloak import KeycloakError, KeycloakOpenID
from fastapi.security import OAuth2PasswordBearer
from apps.auth.models import *
from apps.auth.service import *
from core.auth.models import *
from core.auth.service import create_cookie
from api.deps import get_keycloak
from config import keycloak_openid
from jose import JWTError
import logging

# Setup logging
logger = logging.getLogger(__name__)

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

state_store = {}

# @router.post("/api/login", response_model=TokenResponse)
# async def login(username: str, password: str, keycloak: KeycloakOpenID):
#     """Handle user login"""
#     try:
#         token = await keycloak.token(username, password)
#         return TokenResponse(
#             access_token=token["access_token"],
#             refresh_token=token["refresh_token"],
#             expires_in=token.get("expires_in", 300)
#         )
#     except KeycloakError as e:
#         logger.error(f"Login failed for user {username}: {str(e)}")
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid credentials"
#         )

@router.get("/login")
async def login_redirect(request: Request):
    """Initiate OAuth2 Authorization Code flow"""
    try:
        # Generate state parameter to prevent CSRF
        state = secrets.token_urlsafe(32)
        
        # Store state temporarily (with expiration in production)
        state_store[state] = True
        
        # Build authorization URL
        auth_url = keycloak_openid.auth_url(
            redirect_uri=str(request.url_for('oauth_callback')),
            state=state,
            scope="openid profile email"
        )
        
        return RedirectResponse(auth_url)
    except Exception as e:
        logger.error(f"Failed to initiate auth flow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate authentication"
        )
    
@router.get("/oauth-callback")
async def oauth_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
):
    """Handle OAuth2 callback and token exchange"""
    try:
        # Verify state parameter
        if state not in state_store:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid state parameter"
            )
        
        del state_store[state]
        
        # Exchange authorization code for tokens
        token = keycloak_openid.token(
            grant_type=["authorization_code"],
            code=code,
            redirect_uri=str(request.url_for('oauth_callback'))
        )

        # Set access token cookie
        access_token_cookie = AccessTokenCookie(
            value=token['access_token'],
            max_age=token.get("expires_in", 300),
        )
        create_cookie(response, access_token_cookie)
        
        # Set refresh token cookie
        refresh_token_cookie = RefreshTokenCookie(
            value=token['refresh_token']
        )
        create_cookie(response, refresh_token_cookie)
        
        # To verify cookies were set, you can check the response headers
        logger.debug(f"Response headers: {response.headers}")
        
        return RedirectResponse(
            url="/",
            status_code=status.HTTP_303_SEE_OTHER,
            headers=response.headers
        )
        
    except Exception as e:
        logger.error(f"Token exchange failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

# @router.post("/api/onboard", response_model=TokenResponse)
# async def onboard(
#     password_change: TemporaryPasswordChange,
#     keycloak: KeycloakOpenID
# ):
#     """
#     Handle first-time login flow where users change their temporary password.
    
#     This endpoint:
#     1. Attempts to login with temporary password
#     2. Verifies if password change is required
#     3. Changes the password
#     4. Returns new access tokens
#     """
#     try:
#         # First, try to get a token with the temporary password
#         initial_token = await keycloak.token(
#             username=password_change.username,
#             password=password_change.temporary_password
#         )

#         # Check if password change is required
#         user_info = await keycloak.introspect(initial_token['access_token'])
        
#         if not user_info.get('required_actions', []) or 'UPDATE_PASSWORD' not in user_info.get('required_actions', []):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Password change not required for this user"
#             )

#         # Change the password using admin API
#         user_id = user_info['sub']
#         await keycloak.admin_request(
#             url=f"/users/{user_id}/reset-password",
#             method="PUT",
#             data={
#                 "type": "password",
#                 "value": password_change.new_password,
#                 "temporary": False
#             }
#         )

#         # Remove the UPDATE_PASSWORD required action
#         await keycloak.admin_request(
#             url=f"/users/{user_id}",
#             method="PUT",
#             data={
#                 "requiredActions": [
#                     action for action in user_info.get('required_actions', [])
#                     if action != 'UPDATE_PASSWORD'
#                 ]
#             }
#         )

#         # Get new tokens with the new password
#         new_token = await keycloak.token(
#             username=password_change.username,
#             password=password_change.new_password
#         )

#         return TokenResponse(
#             access_token=new_token["access_token"],
#             refresh_token=new_token["refresh_token"],
#             expires_in=new_token.get("expires_in", 300)
#         )

#     except KeycloakError as e:
#         logger.error(f"Onboarding failed for user {password_change.username}: {str(e)}")
        
#         if "Invalid user credentials" in str(e):
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid temporary password"
#             )
#         elif "Password policy not met" in str(e):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="New password does not meet policy requirements"
#             )
        
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Failed to complete onboarding process"
#         )
#     except Exception as e:
#         logger.error(f"Unexpected error during onboarding: {str(e)}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="An unexpected error occurred"
#         )

# # Optional: Add an endpoint to check if a user needs to change their password
# @router.get("/api/onboard/required/{username}")
# async def check_onboard_required(
#     username: str,
#     keycloak: KeycloakOpenID
# ):
#     """
#     Check if a user needs to complete the onboarding process
#     (i.e., change their temporary password)
#     """
#     try:
#         # Find user by username
#         users = await keycloak.admin_request(
#             url="/users",
#             method="GET",
#             params={"username": username}
#         )
        
#         if not users:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail="User not found"
#             )
        
#         user = users[0]
#         required_actions = user.get('requiredActions', [])
        
#         return {
#             "onboarding_required": 'UPDATE_PASSWORD' in required_actions,
#             "required_actions": required_actions
#         }
        
#     except KeycloakError as e:
#         logger.error(f"Failed to check onboarding status: {str(e)}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to check onboarding status"
#         )

@router.post("/token", response_model=TokenResponse)
async def get_token(grant_data: GrantRequest): # keycloak: KeycloakOpenID = Depends(get_keycloak)
    """Handle token requests (useful for client credentials flow)"""
    try:
        token = await keycloak_openid.token(
            grant_type=["client_credentials"],
            client_id=grant_data.client_id,
            client_secret=grant_data.client_secret
        )
        return TokenResponse(
            access_token=token["access_token"],
            refresh_token=token.get("refresh_token", ""),
            expires_in=token.get("expires_in", 300)
        )
    except KeycloakError as e:
        logger.error(f"Token request failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

@router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    """Refresh access token using refresh token from cookie"""
    try:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No refresh token provided"
            )
        
        token = keycloak_openid.refresh_token(refresh_token)
        
        # Set new access token cookie
        access_token_cookie = AccessTokenCookie(
            value=token["access_token"],
            max_age=token.get("expires_in", 300),
            expires=token.get("expires_in", 300)
        )
        create_cookie(response, access_token_cookie)
        
        # Optionally update refresh token if provided
        if "refresh_token" in token:
            refresh_token_cookie = RefreshTokenCookie(
                value=token["refresh_token"]
            )
            create_cookie(response, refresh_token_cookie)
        
        return {"message": "Token refreshed successfully"}
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
@router.post("/reset")
async def reset_password(email: EmailStr):
    """Handle password reset requests"""
    try:
        # Find user by email
        users = await keycloak_openid.admin_request(
            url="/users",
            method="GET",
            params={"email": email}
        )
        
        if not users:
            # Return success even if email not found to prevent email enumeration
            return {"message": "If the email exists, a reset link has been sent"}
            
        user_id = users[0]["id"]
        
        # Send password reset email
        await keycloak_openid.admin_request(
            url=f"/users/{user_id}/execute-actions-email",
            method="PUT",
            data=["UPDATE_PASSWORD"]
        )
        
        return {"message": "If the email exists, a reset link has been sent"}
    except KeycloakError as e:
        logger.error(f"Password reset failed: {str(e)}")
        # Still return success to prevent email enumeration
        return {"message": "If the email exists, a reset link has been sent"}

@router.get("/logout")
async def logout(request: Request, response: Response):
    """
    Logout user from both the application and Keycloak.
    Uses cookie classes for consistent configuration.
    """
    try:
        # Get tokens from cookies
        refresh_token = request.cookies.get("refresh_token")
        
        if refresh_token:
            try:
                # Logout from Keycloak - this invalidates the refresh token
                keycloak_openid.logout(refresh_token)
            except Exception as e:
                logger.warning(f"Keycloak logout failed: {str(e)}")
        
        # Get cookie configurations from the classes
        access_cookie_config = AccessTokenCookie().model_dump(exclude={"value", "max_age", "expires"})
        refresh_cookie_config = RefreshTokenCookie().model_dump(exclude={"value", "max_age", "expires"})
        
        # Delete cookies using configurations from the classes
        response.delete_cookie(**access_cookie_config)
        
        response.delete_cookie(**refresh_cookie_config)
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )