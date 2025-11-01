import os
import base64
import hashlib
import secrets
import time
from typing import Optional, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")

COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "localhost")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")
ACCESS_TOKEN_COOKIE = os.getenv("ACCESS_TOKEN_COOKIE", "sb_access_token")
REFRESH_TOKEN_COOKIE = os.getenv("REFRESH_TOKEN_COOKIE", "sb_refresh_token")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_ANON_KEY in environment")

# Supabase clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
supabase_admin: Optional[Client] = (
    create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) if SUPABASE_SERVICE_ROLE_KEY else None
)

app = FastAPI(title="Auth Backend with Supabase + FastAPI")

# CORS setup (adjust for your frontend domain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_BASE_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# In-memory store for OAuth PKCE state -> code_verifier (demo-only; use redis for production)
OAUTH_STATE_STORE: Dict[str, Dict[str, Any]] = {}  # state: {"code_verifier": str, "expires_at": int}

# --------- Models ---------
class EmailPasswordSignUp(BaseModel):
    email: EmailStr
    password: str
    data: Optional[Dict[str, Any]] = None  # optional user metadata

class EmailPasswordSignIn(BaseModel):
    email: EmailStr
    password: str

class MagicLinkRequest(BaseModel):
    email: EmailStr
    redirect_to: Optional[str] = None  # defaults to API_BASE_URL + /auth/oauth/callback

class VerifyEmailOtp(BaseModel):
    email: EmailStr
    token: str  # code received by email

class PhoneSignUp(BaseModel):
    phone: str
    password: Optional[str] = None  # Supabase can do passwordless OTP; password optional
    data: Optional[Dict[str, Any]] = None

class PhoneSignInOtp(BaseModel):
    phone: str

class VerifyPhoneOtp(BaseModel):
    phone: str
    token: str  # code received by SMS

class PasswordResetRequest(BaseModel):
    email: EmailStr
    redirect_to: Optional[str] = None

class PasswordUpdateRequest(BaseModel):
    new_password: str

class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None  # if not provided, read from cookie

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

# --------- Dependencies ---------
async def get_current_user(request: Request) -> Dict[str, Any]:
    token = extract_access_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token")
    # Supabase auth.get_user(jwt) returns user info
    try:
        user_resp = supabase.auth.get_user(token)
        if not user_resp or not getattr(user_resp, "user", None):
            raise HTTPException(status_code=401, detail="Invalid token")
        # Convert to plain dict for response
        user = user_resp.user
        return {
            "id": user.id,
            "email": user.email,
            "phone": user.phone,
            "user_metadata": user.user_metadata,
            "app_metadata": user.app_metadata,
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token invalid or expired: {e}")

# --------- Routes ---------
@app.get("/health")
def health():
    return {"status": "ok"}

# Email/password signup
@app.post("/auth/signup")
def signup(payload: EmailPasswordSignUp):
    try:
        res = supabase.auth.sign_up({"email": payload.email, "password": payload.password, "data": payload.data or {}})
        # If email confirmations are enabled, session will be None
        return {
            "user": {"id": res.user.id, "email": res.user.email},
            "session": bool(res.session),
            "message": "Signup successful. Check your email to confirm your account." if not res.session else "Signup and session created",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Email/password sign-in
@app.post("/auth/signin")
def signin(payload: EmailPasswordSignIn, response: Response):
    try:
        res = supabase.auth.sign_in_with_password({"email": payload.email, "password": payload.password})
        if not res.session:
            raise HTTPException(status_code=400, detail="No session returned")
        set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "email": res.user.email}, "expires_in": res.session.expires_in}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# Sign out
@app.post("/auth/signout")
def signout(response: Response):
    try:
        # Best-effort server-side logout; cookie clearing is the key part for the client
        try:
            supabase.auth.sign_out()
        except Exception:
            pass
        clear_session_cookies(response)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Get current user (protected)
@app.get("/auth/me")
async def me(user: Dict[str, Any] = Depends(get_current_user)):
    return {"user": user}

# Refresh session tokens
@app.post("/auth/refresh")
def refresh_tokens(payload: RefreshRequest, response: Response, request: Request):
    refresh_token = payload.refresh_token or request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh token")
    try:
        res = supabase.auth.refresh_session(refresh_token)
        if not res.session:
            raise HTTPException(status_code=400, detail="No new session")
        set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "email": res.user.email}, "expires_in": res.session.expires_in}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# Magic link (email OTP) request
@app.post("/auth/magiclink")
def magic_link(payload: MagicLinkRequest):
    redirect_to = payload.redirect_to or f"{API_BASE_URL}/auth/oauth/callback"
    try:
        supabase.auth.sign_in_with_otp({"email": payload.email, "options": {"email_redirect_to": redirect_to}})
        return {"message": "Magic link sent if the email exists"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Verify email OTP code (if you opt for code entry instead of link)
@app.post("/auth/verify-email-otp")
def verify_email_otp(payload: VerifyEmailOtp, response: Response):
    try:
        res = supabase.auth.verify_otp({"email": payload.email, "token": payload.token, "type": "email"})
        if not res.session:
            raise HTTPException(status_code=400, detail="Verification failed: no session")
        set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "email": res.user.email}}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Phone signup (triggers SMS verification)
@app.post("/auth/signup-phone")
def signup_phone(payload: PhoneSignUp):
    try:
        res = supabase.auth.sign_up({"phone": payload.phone, "password": payload.password, "data": payload.data or {}})
        return {"user": {"id": res.user.id, "phone": res.user.phone}, "message": "Signup started. Verify via SMS OTP."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Phone sign-in (OTP)
@app.post("/auth/signin-phone-otp")
def signin_phone_otp(payload: PhoneSignInOtp):
    try:
        # Sends OTP to phone
        supabase.auth.sign_in_with_otp({"phone": payload.phone})
        return {"message": "OTP sent via SMS if phone is registered"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Verify phone OTP
@app.post("/auth/verify-phone-otp")
def verify_phone_otp(payload: VerifyPhoneOtp, response: Response):
    try:
        res = supabase.auth.verify_otp({"phone": payload.phone, "token": payload.token, "type": "sms"})
        if not res.session:
            raise HTTPException(status_code=400, detail="Verification failed: no session")
        set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "phone": res.user.phone}}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Request password reset
@app.post("/auth/reset-password")
def reset_password(payload: PasswordResetRequest):
    redirect_to = payload.redirect_to or f"{FRONTEND_BASE_URL}/reset-password"
    try:
        supabase.auth.reset_password_for_email(payload.email, {"redirect_to": redirect_to})
        return {"message": "If the email exists, a reset link was sent"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Update password (requires authenticated user)
@app.post("/auth/update-password")
async def update_password(payload: PasswordUpdateRequest, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        supabase.auth.update_user({"password": payload.new_password})
        return {"message": "Password updated"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ---------- OAuth (PKCE) ----------
# Start OAuth flow (redirect user to provider via Supabase authorize)
@app.get("/auth/oauth/{provider}/start")
def oauth_start(provider: str, request: Request):
    # Generate PKCE values
    code_verifier = generate_pkce_verifier()
    code_challenge = compute_code_challenge(code_verifier)
    state = base64url_encode(secrets.token_bytes(24))
    # Store code_verifier in memory keyed by state (expires in 10 min)
    OAUTH_STATE_STORE[state] = {"code_verifier": code_verifier, "expires_at": int(time.time()) + 600}
    # Build authorize URL
    redirect_uri = f"{API_BASE_URL}/auth/oauth/callback"
    authorize_url = (
        f"{SUPABASE_URL}/auth/v1/authorize"
        f"?provider={provider}"
        f"&redirect_to={redirect_uri}"
        f"&response_type=code"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&state={state}"
    )
    # Return 307 redirect to provider URL (via Supabase)
    return Response(status_code=307, headers={"Location": authorize_url})

# OAuth callback (exchange code -> session)
@app.get("/auth/oauth/callback")
async def oauth_callback(code: Optional[str] = None, state: Optional[str] = None, response: Response = None):
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")
    entry = OAUTH_STATE_STORE.get(state)
    if not entry or int(time.time()) > entry["expires_at"]:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    code_verifier = entry["code_verifier"]
    # Clean up state
    OAUTH_STATE_STORE.pop(state, None)

    redirect_uri = f"{API_BASE_URL}/auth/oauth/callback"
    try:
        token_data = await supabase_exchange_code_for_session(code, code_verifier, redirect_uri)
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        if not access_token or not refresh_token:
            raise HTTPException(status_code=400, detail="Token exchange failed")

        set_session_cookies(response, access_token, refresh_token, max_age=expires_in)
        # Redirect to your frontend post-auth page
        return Response(status_code=307, headers={"Location": f"{FRONTEND_BASE_URL}/auth/success"})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))