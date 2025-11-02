from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
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
