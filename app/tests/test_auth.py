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
from app.core.security import decode_token
from jose import jwt
from datetime import datetime, timedelta
from app.core.config import settings
from app.database.models import User
import pyotp

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


def verify_latest_user(client, email: str):
    db = TestingSessionLocal()
    token = db.query(User).filter_by(email=email).first().verification_token
    db.close()
    res = client.post("/auth/verify", json={"token": token})
    assert res.status_code == 200


def test_login_fails_if_not_verified(client):
    client.post(
        "/auth/register",
        json={"username": "unv", "email": "unv@example.com", "password": "secret123"},
    )
    res = client.post(
        "/auth/login",
        json={"email": "unv@example.com", "password": "secret123"},
    )
    assert res.status_code == 400
    verify_latest_user(client, "unv@example.com")


def test_register_login_me_refresh_flow(client):
    res = client.post(
        "/auth/register",
        json={"username": "alice", "email": "alice@example.com", "password": "secret123"},
    )
    assert res.status_code == 200
    data = res.json()
    user_id = data["id"]
    assert data["role"] == "user"

    verify_latest_user(client, "alice@example.com")

    res = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "secret123"},
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


def test_users_endpoint_requires_admin(client):
    client.post(
        "/auth/register",
        json={"username": "bob", "email": "bob@example.com", "password": "secret123"},
    )

    verify_latest_user(client, "bob@example.com")

    res = client.post(
        "/auth/login",
        json={"email": "bob@example.com", "password": "secret123"},
    )
    tokens = res.json()

    res = client.get("/users/")
    assert res.status_code == 401

    res = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert res.status_code == 403


def test_admin_can_access_users_endpoint(client):
    client.post(
        "/auth/register",
        json={"username": "admin", "email": "admin@example.com", "password": "secret123"},
    )

    verify_latest_user(client, "admin@example.com")

    # elevate user to admin role
    db = TestingSessionLocal()
    user = db.query(User).filter_by(email="admin@example.com").first()
    user.role = "admin"
    db.commit()
    db.close()

    res = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "secret123"},
    )
    tokens = res.json()

    res = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_refresh_token_cannot_access_protected_routes(client):
    client.post(
        "/auth/register",
        json={"username": "eve", "email": "eve@example.com", "password": "secret123"},
    )

    verify_latest_user(client, "eve@example.com")

    res = client.post(
        "/auth/login",
        json={"email": "eve@example.com", "password": "secret123"},
    )
    tokens = res.json()

    refresh_headers = {"Authorization": f"Bearer {tokens['refresh_token']}"}

    res = client.get("/auth/me", headers=refresh_headers)
    assert res.status_code == 401

    res = client.get("/users/", headers=refresh_headers)
    assert res.status_code == 401


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


def test_refresh_endpoint_requires_refresh_token(client):
    client.post(
        "/auth/register",
        json={"username": "frank", "email": "frank@example.com", "password": "secret123"},
    )

    verify_latest_user(client, "frank@example.com")
    res = client.post(
        "/auth/login",
        json={"email": "frank@example.com", "password": "secret123"},
    )
    tokens = res.json()

    # Attempt refresh using access token should fail
    access_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    res = client.post("/auth/refresh", headers=access_headers)
    assert res.status_code == 401


def test_refresh_generates_new_identifier(client):
    client.post(
        "/auth/register",
        json={"username": "gina", "email": "gina@example.com", "password": "secret123"},
    )

    verify_latest_user(client, "gina@example.com")
    res = client.post(
        "/auth/login",
        json={"email": "gina@example.com", "password": "secret123"},
    )
    tokens = res.json()
    orig_jti = decode_token(tokens["refresh_token"])["jti"]

    refresh_headers = {"Authorization": f"Bearer {tokens['refresh_token']}"}
    res = client.post("/auth/refresh", headers=refresh_headers)
    assert res.status_code == 200
    new_tokens = res.json()
    new_jti = decode_token(new_tokens["refresh_token"])["jti"]
    assert new_jti != orig_jti


def test_logout_rejects_invalid_token_type(client):
    client.post(
        "/auth/register",
        json={"username": "henry", "email": "henry@example.com", "password": "secret123"},
    )

    payload = {
        "sub": "1",
        "type": "invalid",
        "jti": "x",
        "exp": datetime.utcnow() + timedelta(minutes=5),
    }
    invalid_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    res = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {invalid_token}"},
    )
    assert res.status_code == 401


def test_logout_rejects_unknown_user(client):
    client.post(
        "/auth/register",
        json={"username": "iris", "email": "iris@example.com", "password": "secret123"},
    )

    payload = {
        "sub": "9999",
        "type": "access",
        "jti": "y",
        "exp": datetime.utcnow() + timedelta(minutes=5),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    res = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 401


def test_google_oauth_login(client, monkeypatch):
    monkeypatch.setattr(
        "app.modules.auth.routers.fetch_google_user",
        lambda code: ("g@example.com", "guser"),
    )
    res = client.post("/auth/google", json={"code": "dummy"})
    assert res.status_code == 200
    tokens = res.json()
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res.status_code == 200
    assert res.json()["email"] == "g@example.com"


def test_facebook_oauth_login(client, monkeypatch):
    monkeypatch.setattr(
        "app.modules.auth.routers.fetch_facebook_user",
        lambda code: ("f@example.com", "fuser"),
    )
    res = client.post("/auth/facebook", json={"code": "dummy"})
    assert res.status_code == 200
    tokens = res.json()
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res.status_code == 200
    assert res.json()["email"] == "f@example.com"


def test_two_factor_auth_flow(client):
    client.post(
        "/auth/register",
        json={"username": "otp", "email": "otp@example.com", "password": "secret123"},
    )

    verify_latest_user(client, "otp@example.com")

    res = client.post(
        "/auth/login",
        json={"email": "otp@example.com", "password": "secret123"},
    )
    tokens = res.json()

    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    setup_res = client.post("/auth/2fa/setup", headers=headers)
    secret = setup_res.json()["secret"]
    otp_code = pyotp.TOTP(secret).now()
    enable_res = client.post(
        "/auth/2fa/enable",
        json={"otp": otp_code},
        headers=headers,
    )
    assert enable_res.status_code == 200

    res = client.post(
        "/auth/login",
        json={"email": "otp@example.com", "password": "secret123"},
    )
    assert res.status_code == 400

    res = client.post(
        "/auth/login",
        json={
            "email": "otp@example.com",
            "password": "secret123",
            "otp": pyotp.TOTP(secret).now(),
        },
    )
    assert res.status_code == 200
    new_tokens = res.json()
    disable_res = client.post(
        "/auth/2fa/disable",
        json={"otp": pyotp.TOTP(secret).now()},
        headers={"Authorization": f"Bearer {new_tokens['access_token']}"},
    )
    assert disable_res.status_code == 200
