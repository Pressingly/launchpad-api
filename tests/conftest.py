"""Pytest fixtures for launchpad-api tests."""
import pytest
from httpx import AsyncClient, ASGITransport

from src.main import app


@pytest.fixture
async def client():
    """An AsyncClient for hitting the FastAPI app in-process."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
