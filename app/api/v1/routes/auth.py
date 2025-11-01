# from fastapi import FastAPI, HTTPException, Depends, Response, Request
from typing import Optional, Dict, Any
from supabase import create_client, Client
from fastapi import HTTPException, Depends, Response, Request
import secrets
import time
from fastapi import APIRouter
import app.utils.utils as utils
from app.api.v1.routes import deps
from config_sample import SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, API_BASE_URL, FRONTEND_BASE_URL
router = APIRouter()
# Supabase clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
supabase_admin: Optional[Client] = (
    create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) if SUPABASE_SERVICE_ROLE_KEY else None
)
# In-memory store for OAuth PKCE state -> code_verifier (demo-only; use redis for production)
OAUTH_STATE_STORE: Dict[str, Dict[str, Any]] = {}  # state: {"code_verifier": str, "expires_at": int}

# --------- Routes ---------
@router.get("/health")
def health():
    return {"status": "ok"}

# Email/password signup
@router.post("/auth/signup")
def signup(payload: utils.EmailPasswordSignUp):
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
@router.post("/auth/signin")
def signin(payload: utils.EmailPasswordSignIn, response: Response):
    try:
        res = supabase.auth.sign_in_with_password({"email": payload.email, "password": payload.password})
        if not res.session:
            raise HTTPException(status_code=400, detail="No session returned")
        utils.set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "email": res.user.email}, "expires_in": res.session.expires_in}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# Sign out
@router.post("/auth/signout")
def signout(response: Response):
    try:
        # Best-effort server-side logout; cookie clearing is the key part for the client
        try:
            supabase.auth.sign_out()
        except Exception:
            pass
        utils.clear_session_cookies(response)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Get current user (protected)
@router.get("/auth/me")
async def me(user: Dict[str, Any] = Depends(deps.get_current_user)):
    return {"user": user}

# Refresh session tokens
@router.post("/auth/refresh")
def refresh_tokens(payload: utils.RefreshRequest, response: Response, request: Request):
    refresh_token = payload.refresh_token or request.cookies.get(utils.REFRESH_TOKEN_COOKIE)
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh token")
    try:
        res = supabase.auth.refresh_session(refresh_token)
        if not res.session:
            raise HTTPException(status_code=400, detail="No new session")
        utils.set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "email": res.user.email}, "expires_in": res.session.expires_in}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# Magic link (email OTP) request
@router.post("/auth/magiclink")
def magic_link(payload: utils.MagicLinkRequest):
    redirect_to = payload.redirect_to or f"{API_BASE_URL}/auth/oauth/callback"
    try:
        supabase.auth.sign_in_with_otp({"email": payload.email, "options": {"email_redirect_to": redirect_to}})
        return {"message": "Magic link sent if the email exists"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Verify email OTP code (if you opt for code entry instead of link)
@router.post("/auth/verify-email-otp")
def verify_email_otp(payload: utils.VerifyEmailOtp, response: Response):
    try:
        res = supabase.auth.verify_otp({"email": payload.email, "token": payload.token, "type": "email"})
        if not res.session:
            raise HTTPException(status_code=400, detail="Verification failed: no session")
        utils.set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "email": res.user.email}}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Phone signup (triggers SMS verification)
@router.post("/auth/signup-phone")
def signup_phone(payload: utils.PhoneSignUp):
    try:
        res = supabase.auth.sign_up({"phone": payload.phone, "password": payload.password, "data": payload.data or {}})
        return {"user": {"id": res.user.id, "phone": res.user.phone}, "message": "Signup started. Verify via SMS OTP."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Phone sign-in (OTP)
@router.post("/auth/signin-phone-otp")
def signin_phone_otp(payload: utils.PhoneSignInOtp):
    try:
        # Sends OTP to phone
        supabase.auth.sign_in_with_otp({"phone": payload.phone})
        return {"message": "OTP sent via SMS if phone is registered"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Verify phone OTP
@router.post("/auth/verify-phone-otp")
def verify_phone_otp(payload: utils.VerifyPhoneOtp, response: Response):
    try:
        res = supabase.auth.verify_otp({"phone": payload.phone, "token": payload.token, "type": "sms"})
        if not res.session:
            raise HTTPException(status_code=400, detail="Verification failed: no session")
        utils.set_session_cookies(response, res.session.access_token, res.session.refresh_token, max_age=res.session.expires_in or 3600)
        return {"user": {"id": res.user.id, "phone": res.user.phone}}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Request password reset
@router.post("/auth/reset-password")
def reset_password(payload: utils.PasswordResetRequest):
    redirect_to = payload.redirect_to or f"{FRONTEND_BASE_URL}/reset-password"
    try:
        supabase.auth.reset_password_for_email(payload.email, {"redirect_to": redirect_to})
        return {"message": "If the email exists, a reset link was sent"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Update password (requires authenticated user)
@router.post("/auth/update-password")
async def update_password(payload: utils.PasswordUpdateRequest, user: Dict[str, Any] = Depends(deps.get_current_user)):
    try:
        supabase.auth.update_user({"password": payload.new_password})
        return {"message": "Password updated"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ---------- OAuth (PKCE) ----------
# Start OAuth flow (redirect user to provider via Supabase authorize)
@router.get("/auth/oauth/{provider}/start")
def oauth_start(provider: str, request: Request):
    # Generate PKCE values
    code_verifier = utils.generate_pkce_verifier()
    code_challenge = utils.compute_code_challenge(code_verifier)
    state = utils.base64url_encode(secrets.token_bytes(24))
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
@router.get("/auth/oauth/callback")
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
        token_data = await utils.supabase_exchange_code_for_session(code, code_verifier, redirect_uri)
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        if not access_token or not refresh_token:
            raise HTTPException(status_code=400, detail="Token exchange failed")

        utils.set_session_cookies(response, access_token, refresh_token, max_age=expires_in)
        # Redirect to your frontend post-auth page
        return Response(status_code=307, headers={"Location": f"{FRONTEND_BASE_URL}/auth/success"})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))