from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from api.errors.errors import AuthenticationError
import logging

logger = logging.getLogger(__name__)

async def authentication_exception_handler(request: Request, exc: AuthenticationError):
    logger.error(f"Handling AuthenticationError: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )