import pytest
from httpx import AsyncClient
from src.main import app
from src.models.auth import User
from src.core.security import get_password_hash

@pytest.mark.asyncio
async def test_register(client, db_session):
    """Test user registration endpoint."""
    response = await client.post("/api/v1/auth/register", json={
        "email": "test@example.com",
        "full_name": "Test User",
        "password": "password123",
        "username": "testuser",
        "role": "user"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["full_name"] == "Test User"
    assert data["role"] == "user"

    # Verify user in database
    user = db_session.query(User).filter(User.email == "test@example.com").first()
    assert user is not None
    assert user.email == "test@example.com"

@pytest.mark.asyncio
async def test_login(client, db_session):
    """Test user login endpoint."""
    # Create a user
    await client.post("/api/v1/auth/register", json={
        "email": "login@example.com",
        "password": "password123",
        "username": "loginuser"
    })

    response = await client.post("/api/v1/auth/login", json={
        "identifier": "loginuser",
        "password": "password123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_login_invalid_credentials(client):
    """Test login with invalid credentials."""
    response = await client.post("/api/v1/auth/login", json={
        "identifier": "nonexistent",
        "password": "wrong"
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect credentials"