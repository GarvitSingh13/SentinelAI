from fastapi import APIRouter
from app.api.v1 import auth, flows, incidents, stats, stream, blacklist

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(flows.router)
api_router.include_router(incidents.router)
api_router.include_router(stats.router)
api_router.include_router(stream.router, prefix="/stream", tags=["Streaming Pipeline"])
api_router.include_router(blacklist.router, prefix="/blacklist", tags=["Active Blacklist"])
