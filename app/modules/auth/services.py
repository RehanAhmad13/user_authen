from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
)
import re
from app.modules.auth.schemas import UserCreate, Role
import pyotp
from app.database.models import User
from . import repository
from app.modules.audit import repository as audit_repository
from uuid import uuid4
from app.modules.auth.validation import validate_name, validate_email, validate_password



############# POST /auth/register API #############


def create_user(user_in: UserCreate, db: Session):
    # Step 0 — Validate name & email
    validate_name(user_in.username)
    validate_email(user_in.email)

    # Step 1 — Check for duplicates
    if repository.get_user_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if repository.get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already taken")

    # Step 2 — Validate password
    validate_password(user_in.password)

    # Step 3 — Create user
    sanitized = user_in.copy(update={"role": Role.user})
    user = repository.create_user(db, sanitized)

    # Step 4 — Log registration action
    audit_repository.create_log(db, user.id, "register")

    # Print token to console for development
    print(f"[INFO] Verification token for {user.email}: {user.verification_token}")

    return user


############# POST /auth/verify API #############


def verify_email(token: str, db: Session) -> User:
    """Verify a user's email using the provided token."""
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.is_verified = True
    user.verification_token = None
    db.commit()
    db.refresh(user)
    audit_repository.create_log(db, user.id, "verify_email")
    return user

############ POST /auth/login API #############


def authenticate_user(email: str, password: str, db: Session):
    user = repository.get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def login_user(email: str, password: str, db: Session, otp: str | None = None) -> dict:
    """Authenticate the user and return JWT tokens."""
    user = authenticate_user(email, password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    if not user.is_verified:
        raise HTTPException(status_code=400, detail="Email not verified")
    if user.two_factor_enabled:
        if not otp:
            raise HTTPException(status_code=400, detail="OTP required")
        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(otp):
            raise HTTPException(status_code=400, detail="Invalid OTP")
    audit_repository.create_log(db, user.id, "login")
    return generate_tokens(user)



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




def setup_two_factor(user: User, db: Session) -> str:
    secret = pyotp.random_base32()
    user.two_factor_secret = secret
    user.two_factor_enabled = False
    db.commit()
    db.refresh(user)
    audit_repository.create_log(db, user.id, "2fa_setup")
    return secret


def enable_two_factor(user: User, otp: str, db: Session) -> User:
    if not user.two_factor_secret:
        raise HTTPException(status_code=400, detail="2FA not configured")
    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    user.two_factor_enabled = True
    db.commit()
    db.refresh(user)
    audit_repository.create_log(db, user.id, "2fa_enable")
    return user


def disable_two_factor(user: User, otp: str, db: Session) -> User:
    if not user.two_factor_secret or not user.two_factor_enabled:
        raise HTTPException(status_code=400, detail="2FA not enabled")
    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    user.two_factor_secret = None
    user.two_factor_enabled = False
    db.commit()
    db.refresh(user)
    audit_repository.create_log(db, user.id, "2fa_disable")
    return user



def _get_or_create_oauth_user(email: str, username: str, db: Session) -> User:
    user = repository.get_user_by_email(db, email)
    if user:
        return user
    dummy_password = uuid4().hex + "A1"  # ensures password validation
    user_in = UserCreate(username=username, email=email, password=dummy_password)
    user = repository.create_user(db, user_in)
    user.is_verified = True
    user.verification_token = None
    db.commit()
    db.refresh(user)
    audit_repository.create_log(db, user.id, "register")
    return user


def oauth_login(email: str, username: str, db: Session) -> dict:
    user = _get_or_create_oauth_user(email, username, db)
    audit_repository.create_log(db, user.id, "oauth_login")
    return generate_tokens(user)

