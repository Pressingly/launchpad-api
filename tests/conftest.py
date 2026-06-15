"""Pytest fixtures for launchpad-api tests."""
import pytest
from httpx import AsyncClient, ASGITransport

from src import db
from src.main import app


@pytest.fixture(autouse=True)
async def _reset_pool_per_test():
    """Pytest-asyncio creates a fresh event loop per test, so we must close
    and recreate the asyncpg pool for each one — otherwise the pool's
    connections are tied to a dead loop."""
    yield
    await db.close_pool()


@pytest.fixture
async def client():
    """An AsyncClient for hitting the FastAPI app in-process."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
