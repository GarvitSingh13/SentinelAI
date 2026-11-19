import pytest_asyncio
from sqlalchemy import select
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User

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
