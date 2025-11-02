from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from app.api.v1.routes import handler
import config_sample as config
# Loading environment variables
if not config.SUPABASE_URL or not config.SUPABASE_ANON_KEY:
    raise RuntimeError("Missing config.SUPABASE_URL or config.SUPABASE_ANON_KEY in environment")

# Supabase clients
supabase: Client = create_client(config.SUPABASE_URL, config.SUPABASE_ANON_KEY)
supabase_admin: Optional[Client] = (
    create_client(config.SUPABASE_URL, config.SUPABASE_SERVICE_ROLE_KEY) if config.SUPABASE_SERVICE_ROLE_KEY else None
)

app = FastAPI(title="Auth Backend with Supabase + FastAPI")

# CORS setup (adjust for your frontend domain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.FRONTEND_BASE_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(handler.api_router)

# Export the app as "main" for ASGI servers
main = app
