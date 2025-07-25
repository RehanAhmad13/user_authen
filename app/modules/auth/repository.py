from typing import List, Optional
from sqlalchemy.orm import Session

from app.database.models import User
from uuid import uuid4
from app.core.security import hash_password
from .schemas import UserCreate


def get_user(db: Session, user_id: int) -> Optional[User]:
    """Return a user by ID or ``None`` if not found."""
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Return a user by email or ``None`` if not found."""
    return db.query(User).filter(User.email == email).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Return a user by username or ``None`` if not found."""
    return db.query(User).filter(User.username == username).first()


def list_users(db: Session) -> List[User]:
    """Return all users."""
    return db.query(User).all()


def create_user(db: Session, user_in: UserCreate) -> User:
    """Create and persist a new user based on the provided schema."""
    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=user_in.role.value,
        is_active=True,
        is_verified=False,
        verification_token=uuid4().hex,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
