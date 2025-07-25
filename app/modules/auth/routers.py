from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.modules.auth.schemas import (
    UserCreate,
    UserOut,
    Token,
    LoginRequest,
    VerifyRequest,
    OTPRequest,
    TwoFactorSecretOut,
)

from app.core.dependencies import (
    get_db,
    get_current_user,
    get_current_user_from_refresh_token,
    oauth2_scheme,
)
from app.modules.auth.services import (
    create_user,
    login_user,
    generate_tokens,
    oauth_login,
    verify_email,
    setup_two_factor,
    enable_two_factor,
    disable_two_factor,
)
from app.modules.auth.social import fetch_google_user, fetch_facebook_user
from app.core.security import revoke_token, decode_token
from app.database.models import User


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    return create_user(user, db)


@router.post("/verify", response_model=UserOut)
def verify(request: VerifyRequest, db: Session = Depends(get_db)):
    return verify_email(request.token, db)


@router.post("/login", response_model=Token)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    return login_user(credentials.email, credentials.password, db, credentials.otp)


@router.post("/google", response_model=Token)
def google_login(payload: dict, db: Session = Depends(get_db)):
    code = payload.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    email, username = fetch_google_user(code)
    return oauth_login(email, username, db)


@router.post("/facebook", response_model=Token)
def facebook_login(payload: dict, db: Session = Depends(get_db)):
    code = payload.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    email, username = fetch_facebook_user(code)
    return oauth_login(email, username, db)


@router.post("/refresh", response_model=Token)
def refresh(current_user: User = Depends(get_current_user_from_refresh_token)):
    return generate_tokens(current_user)


@router.post("/2fa/setup", response_model=TwoFactorSecretOut)
def two_factor_setup(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    secret = setup_two_factor(current_user, db)
    return {"secret": secret}


@router.post("/2fa/enable", response_model=UserOut)
def two_factor_enable(
    otp: OTPRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return enable_two_factor(current_user, otp.otp, db)


@router.post("/2fa/disable", response_model=UserOut)
def two_factor_disable(
    otp: OTPRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return disable_two_factor(current_user, otp.otp, db)


@router.post("/logout")
def logout(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    payload = decode_token(token)
    token_type = payload.get("type")
    user_id = payload.get("sub")

    if token_type not in {"access", "refresh"} or user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    revoke_token(token)
    from app.modules.audit.repository import create_log
    create_log(db, user.id, "logout")
    return {"detail": "Token revoked"}


@router.get("/me", response_model=UserOut)
def get_me(current_user: UserOut = Depends(get_current_user)):
    return current_user
