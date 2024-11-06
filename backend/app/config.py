from core.auth.models import KeycloakConfig
from keycloak import KeycloakOpenID

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
        "/redoc",
        "/out"
    }
)

keycloak_openid = KeycloakOpenID(
            server_url=keycloak_config.SERVER_URL,
            client_id=keycloak_config.CLIENT_ID,
            realm_name=keycloak_config.REALM,
            client_secret_key=keycloak_config.CLIENT_SECRET
        )