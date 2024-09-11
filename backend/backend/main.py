
from urllib.parse import urlencode
import requests
import time
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request, Depends, HTTPException, Response, Cookie
from fastapi.responses import RedirectResponse
from fastapi.security.oauth2 import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from typing import Optional
from uuid import uuid4

app = FastAPI()


class Settings(BaseSettings):
    github_client_id: str
    github_client_secret: str
    redirect_uri: str
    
    jwt_secret_key: str
    jwt_algorithm: str = "RS256"
    jwt_access_token_expire_minutes: int = 30


settings = Settings()


# RSA keys for JWKS
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serializing private and public keys
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# JWKS endpoint
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": public_key.public_numbers().n,
            "e": public_key.public_numbers().e,
        }
    ]
}


class Token(BaseModel):
    access_token: str
    token_type: str


@app.get("/auth/login")
def github_login(response: Response):
    # Generate random state and store in a cookie
    state = str(uuid4())
    response.set_cookie("oauth_state", state, httponly=True)
    
    # GitHub OAuth login URL
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": settings.redirect_uri,
        "state": state,
        "scope": "user"
    }
    url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    return RedirectResponse(url)


@app.get("/auth/callback")
def github_callback(code: str, state: str, oauth_state: Optional[str] = Cookie(None), response: Response = None):
    # Verify the state
    if oauth_state != state:
        raise HTTPException(status_code=400, detail="Invalid state")

    # Exchange code for access token
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": settings.github_client_id,
        "client_secret": settings.github_client_secret,
        "code": code,
        "redirect_uri": settings.redirect_uri,
        "state": state,
    }
    token_res = requests.post(token_url, headers=headers, data=data)
    token_res_data = token_res.json()

    if "access_token" not in token_res_data:
        raise HTTPException(status_code=400, detail="Failed to get access token")

    # Get GitHub user information
    access_token = token_res_data["access_token"]
    user_info_url = "https://api.github.com/user"
    user_info_res = requests.get(user_info_url, headers={"Authorization": f"Bearer {access_token}"})
    user_info = user_info_res.json()

    # Mint your own token
    token_data = {
        "sub": user_info["id"],
        "name": user_info["login"],
        "exp": time.time() + settings.jwt_access_token_expire_minutes * 60,
        "iat": time.time(),
    }
    jwt_token = jwt.encode(token_data, private_key_pem, algorithm=settings.jwt_algorithm)

    # Set token in cookie
    response = RedirectResponse(url="/")
    response.set_cookie("auth_token", jwt_token, httponly=True)

    return response


@app.get("/.well-known/jwks.json")
def jwks_endpoint():
    # Host the JWKS public keys for clients
    return jwks


@app.get("/")
def home():
    return {"message": "Welcome! Authenticate using /auth/login"}