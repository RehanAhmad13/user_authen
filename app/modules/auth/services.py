from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
)
import re
from app.modules.auth.schemas import UserCreate, Role
from app.database.models import User
from . import repository

PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")


def _validate_password(password: str) -> None:
    if not PASSWORD_RE.match(password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long and contain both letters and numbers",
        )


def create_user(user_in: UserCreate, db: Session):
    if repository.get_user_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if repository.get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    _validate_password(user_in.password)

    sanitized = user_in.copy(update={"role": Role.user})
    return repository.create_user(db, sanitized)

def authenticate_user(email: str, password: str, db: Session):
    user = repository.get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def generate_tokens(user: User) -> dict:
    """Return a new access and refresh token pair for the given user."""
    return {
        "access_token": create_access_token(
            data={"sub": str(user.id), "role": user.role}
        ),
        "refresh_token": create_refresh_token(
            data={"sub": str(user.id), "role": user.role}
        ),
        "token_type": "bearer",
    }


def login_user(email: str, password: str, db: Session) -> dict:
    """Authenticate the user and return JWT tokens."""
    user = authenticate_user(email, password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return generate_tokens(user)
