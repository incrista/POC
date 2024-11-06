from fastapi import FastAPI
from core.auth.keycloak import KeycloakMiddleware
from apps.auth.routes import router as auth_router
from apps.app1.routes import router as app1_router
from apps.app2.routes import router as app2_router
from api.errors.errors import *
from api.errors.handlers import *
from config import keycloak_config, keycloak_openid
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Multi-App Backend",
    description="Multi-application backend with Keycloak authentication and role-based authorization",
    version="1.0.0",
    debug=True
)

# keycloak_admin = KeycloakOpenID(
#             server_url=keycloak_config.SERVER_URL,
#             client_id=keycloak_config.CLIENT_ID,
#             realm_name=keycloak_config.REALM,
#             client_secret_key=keycloak_config.CLIENT_SECRET
#         )

app.add_exception_handler(AuthenticationError, authentication_exception_handler)

app.add_middleware(
    KeycloakMiddleware,
    config = keycloak_config,
    keycloak_openid = keycloak_openid
)

app.include_router(auth_router, prefix="/api")
# app.include_router(app1_router, prefix="/api/v1")
# app.include_router(app2_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/")
async def home():
    return {"status": "Open Endpoint Home"}

@app.get("/out")
async def logged_out():
    return {"status": "You are logged out."}