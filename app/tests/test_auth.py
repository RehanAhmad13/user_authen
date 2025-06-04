import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.main import app
from app.database.session import Base
from app.core.dependencies import get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_register_login_me_refresh_flow(client):
    res = client.post(
        "/auth/register",
        json={"username": "alice", "email": "alice@example.com", "password": "secret123"},
    )
    assert res.status_code == 200
    data = res.json()
    user_id = data["id"]
    assert data["role"] == "user"

    res = client.post(
        "/auth/login",
        data={"username": "alice@example.com", "password": "secret123"},
    )
    assert res.status_code == 200
    tokens = res.json()
    assert "access_token" in tokens and "refresh_token" in tokens

    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    res = client.get("/auth/me", headers=headers)
    assert res.status_code == 200
    assert res.json()["id"] == user_id

    res = client.post(
        "/auth/refresh", headers={"Authorization": f"Bearer {tokens['refresh_token']}"}
    )
    assert res.status_code == 200
    new_tokens = res.json()
    assert new_tokens["access_token"]

    # logout and ensure token revoked
    res = client.post(
        "/auth/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert res.status_code == 200

    res = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res.status_code == 401


def test_users_endpoint_requires_token(client):
    client.post(
        "/auth/register",
        json={"username": "bob", "email": "bob@example.com", "password": "secret123"},
    )

    res = client.post(
        "/auth/login",
        data={"username": "bob@example.com", "password": "secret123"},
    )
    tokens = res.json()

    res = client.get("/users/")
    assert res.status_code == 401

    res = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_admin_role_ignored_and_validations(client):
    # Attempt to register as admin should result in normal user role
    res = client.post(
        "/auth/register",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "complex123",
            "role": "admin",
        },
    )
    assert res.status_code == 200
    assert res.json()["role"] == "user"

    # Duplicate username should fail
    res = client.post(
        "/auth/register",
        json={
            "username": "charlie",
            "email": "other@example.com",
            "password": "complex123",
        },
    )
    assert res.status_code == 400

    # Weak password should fail
    res = client.post(
        "/auth/register",
        json={"username": "dave", "email": "dave@example.com", "password": "short"},
    )
    assert res.status_code == 400
