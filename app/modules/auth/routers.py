from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from app.core.dependencies import get_db, get_current_user, oauth2_scheme
from app.modules.auth.schemas import UserCreate, UserOut, Token
from app.modules.auth.services import create_user, login_user, generate_tokens
from app.database.models import User


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    return create_user(user, db)


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    return login_user(form_data.username, form_data.password, db)


@router.post("/refresh", response_model=Token)
def refresh(current_user: User = Depends(get_current_user)):
    return generate_tokens(current_user)


@router.get("/me", response_model=UserOut)
def get_me(current_user: UserOut = Depends(get_current_user)):
    return current_user
