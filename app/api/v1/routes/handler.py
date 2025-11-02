from fastapi import APIRouter
from app.api.v1.routes import auth
api_router = APIRouter()

# Handle all /auth routes
api_router.include_router(auth.router)