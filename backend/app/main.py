from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User
from app.api.router import api_router
from app.ml.classifier import IntrusionClassifier

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: 1. Create database schema
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Seed initial admin user if not present
    async with AsyncSessionLocal() as session:
        stmt = select(User).where(User.email == "admin@sentinelai.com")
        existing_admin = (await session.execute(stmt)).scalar_one_or_none()
        if not existing_admin:
            admin_user = User(
                email="admin@sentinelai.com",
                password_hash=get_password_hash("SentinelSecret2026!"),
                full_name="Lead Security Analyst",
                role="ADMIN"
            )
            session.add(admin_user)
            await session.commit()
            print("✓ Seeded default admin user: admin@sentinelai.com / SentinelSecret2026!")

    # 3. Warm up ML model & explainer
    classifier = IntrusionClassifier.get_instance()
    print(f"✓ SentinelAI ML Engine loaded with {len(classifier.class_names)} classes.")

    yield

    # Shutdown
    await engine.dispose()

app = FastAPI(
    title="SentinelAI — Network Detection & Response Engine",
    description="Real-Time AI-Powered Network Intrusion Detection & Response Platform with Explainable AI (SHAP)",
    version=settings.VERSION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/health", tags=["Health & Status"])
async def health_check():
    return {
        "status": "UP",
        "service": "SentinelAI NDR Engine",
        "version": settings.VERSION,
        "ml_engine": "XGBoost + TreeSHAP Active"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
