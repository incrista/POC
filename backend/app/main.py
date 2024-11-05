from fastapi import FastAPI
from keycloak import KeycloakOpenID
from core.auth.keycloak import KeycloakMiddleware
from core.auth.models import KeycloakConfig
from apps.auth.routes import router as auth_router
from apps.app1.routes import router as app1_router
from apps.app2.routes import router as app2_router
from api.errors.errors import *
from api.errors.handlers import *
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Multi-App Backend",
    description="Multi-application backend with Keycloak authentication and role-based authorization",
    version="1.0.0",
    debug=True
)

keycloak_config = KeycloakConfig(
    CLIENT_ID="fastapi-backend-client",
    CLIENT_SECRET="eymVipgkXLHlViRksmrTFmdlD5cPqG8f",
    SERVER_URL="http://localhost:8080",
    REALM="test",
    OPEN_ENDPOINTS={  # Changed from open_routes list to OPEN_ENDPOINTS set
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc"
    }
)

keycloak_openid = KeycloakOpenID(
            server_url=keycloak_config.SERVER_URL,
            client_id=keycloak_config.CLIENT_ID,
            realm_name=keycloak_config.REALM,
            client_secret_key=keycloak_config.CLIENT_SECRET
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
app.include_router(app1_router, prefix="/api/v1")
app.include_router(app2_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/")
async def home():
    return {"status": "authorized"}