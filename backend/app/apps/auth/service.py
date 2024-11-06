from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from core.auth.models import *
from config import keycloak_openid
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakError, KeycloakOpenID
from jose import JWTError
import logging


logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        user_info = keycloak_openid.decode_token(
            access_token,
            key=keycloak_openid.public_key(),
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_exp": True
            }
        )
        return user_info
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or token expired"
        )
    
