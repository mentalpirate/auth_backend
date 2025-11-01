import os

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
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", f"{API_BASE_URL}/auth/oauth/callback")
