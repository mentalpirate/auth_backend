import base64
import hashlib
import secrets
from fastapi import Request, Response, HTTPException
import httpx
from typing import Optional
from config_sample import (
    SUPABASE_URL,
    COOKIE_DOMAIN,
    COOKIE_SECURE,
    COOKIE_SAMESITE,
    ACCESS_TOKEN_COOKIE,
    REFRESH_TOKEN_COOKIE
)


# --------- Utilities ---------
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def generate_pkce_verifier(length: int = 64) -> str:
    # RFC 7636: verifier is high-entropy cryptographic random string
    return base64url_encode(secrets.token_bytes(length))

def compute_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64url_encode(digest)

def set_session_cookies(response: Response, access_token: str, refresh_token: str, max_age: int = 60 * 60):
    # Supabase tokens usually have ~1 hour expiry; set cookie max-age accordingly
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        domain=COOKIE_DOMAIN,
        secure=COOKIE_SECURE,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        max_age=max_age,
        path="/",
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        domain=COOKIE_DOMAIN,
        secure=COOKIE_SECURE,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        max_age=60 * 60 * 24 * 7,  # refresh tokens typically longer-lived
        path="/",
    )

def clear_session_cookies(response: Response):
    response.delete_cookie(ACCESS_TOKEN_COOKIE, domain=COOKIE_DOMAIN, path="/")
    response.delete_cookie(REFRESH_TOKEN_COOKIE, domain=COOKIE_DOMAIN, path="/")

def extract_access_token(request: Request) -> Optional[str]:
    # Prefer Authorization header; fallback to cookie
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1]
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    return token

async def supabase_exchange_code_for_session(code: str, code_verifier: str, redirect_uri: str):
    # Exchange authorization code for tokens with Supabase GoTrue
    token_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=authorization_code"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            token_url,
            headers={"Content-Type": "application/json"},
            json={
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
            },
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()

