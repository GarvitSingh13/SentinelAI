from fastapi import APIRouter
from app.api.v1 import auth, flows, incidents, stats

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(flows.router)
api_router.include_router(incidents.router)
api_router.include_router(stats.router)
