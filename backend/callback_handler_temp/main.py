from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from typing import Optional
import httpx
import secrets
from pathlib import Path

class Settings(BaseSettings):
    keycloak_server_url: str = "http://localhost:8080"
    keycloak_realm: str = "test"
    client_id: str = "fastapi-backend"
    client_secret: str = "T2yvJxMrOfW7QBhW1yM4WOYvMKjPBhH3"

    class Config:
        env_prefix = "AUTH_"
        env_file = ".env"

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str]
    token_type: str
    expires_in: int
    scope: Optional[str] = None

app = FastAPI(title="Keycloak Direct Grant Auth")
settings = Settings()

# Rest of the code remains unchanged...
templates = Jinja2Templates(directory="templates")

# HTML template for the login page
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
        }
        button:hover {
            background-color: #45a049;
        }
        .error {
            color: red;
            margin-top: 1rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 style="text-align: center; margin-bottom: 2rem;">Login</h2>
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div id="error" class="error"></div>
    </div>

    <script>
        async function handleLogin(event) {
            event.preventDefault();
            const form = event.target;
            const errorDiv = document.getElementById('error');
            
            try {
                const response = await fetch('/token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        'username': form.username.value,
                        'password': form.password.value,
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Authentication failed');
                }
                
                // Store tokens (in memory for this example)
                sessionStorage.setItem('access_token', data.access_token);
                if (data.refresh_token) {
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                }
                
                // Show success and redirect to user info
                window.location.href = '/introspect';
                
            } catch (error) {
                errorDiv.textContent = error.message;
            }
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def login_page():
    """Serve the login page"""
    return LOGIN_HTML

@app.post("/token")
async def get_token(
    username: str = Form(...),
    password: str = Form(...)
):
    """Get access token using direct grant flow"""
    token_url = (
        f"{settings.keycloak_server_url}/realms/{settings.keycloak_realm}"
        f"/protocol/openid-connect/token"
    )
    
    token_data = {
        "grant_type": "password",
        "client_id": settings.client_id,
        "username": username,
        "password": password,
        "scope": "openid profile email"
    }
    
    if settings.client_secret:
        token_data["client_secret"] = settings.client_secret
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(token_url, data=token_data)
            response.raise_for_status()
            return TokenResponse(**response.json())
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid username or password"
                )
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Authentication failed: {e.response.text}"
            )
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error connecting to authentication server: {str(e)}"
            )

@app.get("/introspect", response_class=HTMLResponse)
async def introspect_page():
    """Serve the introspect page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Token Info</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 2rem;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
            }
            pre {
                background: #f4f4f4;
                padding: 1rem;
                border-radius: 4px;
                overflow-x: auto;
            }
            .error {
                color: red;
                margin: 1rem 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Token Information</h2>
            <div id="introspectInfo"></div>
            <div id="error" class="error"></div>
        </div>

        <script>
            async function fetchIntrospect() {
                const token = sessionStorage.getItem('access_token');
                if (!token) {
                    window.location.href = '/';
                    return;
                }

                try {
                    const response = await fetch('/api/introspect', {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });

                    if (!response.ok) {
                        throw new Error('Failed to fetch introspection');
                    }

                    const data = await response.json();
                    document.getElementById('introspectInfo').innerHTML = `
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                    `;
                } catch (error) {
                    document.getElementById('error').textContent = error.message;
                }
            }

            fetchIntrospect();
        </script>
    </body>
    </html>
    """

@app.get("/api/introspect")
async def get_introspection (request: Request):
    """API endpoint to introspect access token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header"
        )
    
    token = auth_header.split(' ')[1]
    print(token)
    introspect_url = (
        f"{settings.keycloak_server_url}/realms/{settings.keycloak_realm}"
        f"/protocol/openid-connect/token/introspect"
    )
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                introspect_url,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={'client_id': settings.client_id,
                        'client_secret': settings.client_secret,
                        'token': token,
                        'token_type_hint': 'access_token'}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            print(e)
            raise HTTPException(
                status_code=401,
                detail="Expired or invalid token"
            )

""" if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) """