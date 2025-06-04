from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
)
from app.modules.auth.schemas import UserCreate
from app.database.models import User
from . import repository

def create_user(user_in: UserCreate, db: Session):
    if repository.get_user_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    return repository.create_user(db, user_in)

def authenticate_user(email: str, password: str, db: Session):
    user = repository.get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def generate_tokens(user: User) -> dict:
    """Return a new access and refresh token pair for the given user."""
    return {
        "access_token": create_access_token(data={"sub": str(user.id)}),
        "refresh_token": create_refresh_token(data={"sub": str(user.id)}),
        "token_type": "bearer",
    }


def login_user(email: str, password: str, db: Session) -> dict:
    """Authenticate the user and return JWT tokens."""
    user = authenticate_user(email, password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    return generate_tokens(user)
