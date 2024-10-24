from fastapi import FastAPI
from core.auth.keycloak import KeycloakMiddleware, KeycloakConfig
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
    client_id="fastapi-backend",
    client_secret="T2yvJxMrOfW7QBhW1yM4WOYvMKjPBhH3",
    server_url="http://localhost:8080",
    realm="test",
    open_routes=[
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc"
    ]
)

@app.exception_handler(HTTPException)
async def global_http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTPException: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

app.add_exception_handler(AuthenticationError, authentication_exception_handler)


app.add_middleware(
    KeycloakMiddleware,
    config=keycloak_config,
    token_expiry_threshold=300
)


app.include_router(app1_router, prefix="/api/v1")
app.include_router(app2_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}