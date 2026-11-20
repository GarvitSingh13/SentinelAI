import pytest_asyncio
from sqlalchemy import select
from httpx import AsyncClient, ASGITransport

from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User
from app.main import app

@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_test_db():
    # Create all tables on postgres
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed default admin user
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

    yield
    await engine.dispose()

@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

@pytest_asyncio.fixture
async def admin_token_headers(client: AsyncClient):
    res = await client.post("/api/v1/auth/login", json={
        "email": "admin@sentinelai.com",
        "password": "SentinelSecret2026!"
    })
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
