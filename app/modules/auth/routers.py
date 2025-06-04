from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.modules.auth.schemas import UserCreate, UserOut, Token, LoginRequest

from app.core.dependencies import (
    get_db,
    get_current_user,
    get_current_user_from_refresh_token,
    oauth2_scheme,
)
from app.modules.auth.services import create_user, login_user, generate_tokens
from app.core.security import revoke_token
from app.database.models import User


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    return create_user(user, db)


@router.post("/login", response_model=Token)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    return login_user(credentials.email, credentials.password, db)


@router.post("/refresh", response_model=Token)
def refresh(current_user: User = Depends(get_current_user_from_refresh_token)):
    return generate_tokens(current_user)


@router.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    revoke_token(token)
    return {"detail": "Token revoked"}


@router.get("/me", response_model=UserOut)
def get_me(current_user: UserOut = Depends(get_current_user)):
    return current_user
