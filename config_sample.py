import os
import dotenv
dotenv.load_dotenv()

SUPABASE_URL=os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY=os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY="your-service-role-key" # optional, avoid if not needed
API_BASE_URL="http://localhost:8000"
FRONTEND_BASE_URL="http://localhost:3000"

COOKIE_DOMAIN="localhost"
COOKIE_SECURE="false"          # true in production (HTTPS)
COOKIE_SAMESITE="lax"          # 'lax' or 'strict' or 'none' (none requires secure=true)
ACCESS_TOKEN_COOKIE="sb_access_token"
REFRESH_TOKEN_COOKIE="sb_refresh_token"