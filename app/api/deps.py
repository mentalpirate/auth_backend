from typing import Any, Dict
from fastapi import Request
from supabase import create_client, Client
from fastapi import HTTPException
from app.utils.utils import extract_access_token
import app.core.config as configs

# Supabase client
url = configs.SUPABASE_URL
key = configs.SUPABASE_ANON_KEY
supabase: Client = create_client(url, key)
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
