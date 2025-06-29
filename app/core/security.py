from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from uuid import uuid4
from app.core.config import settings
from app.database.redis import add_token_to_blacklist, is_token_revoked

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _create_token(data: dict, expires_delta: timedelta, token_type: str) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    jti = str(uuid4())
    to_encode.update({"exp": expire, "type": token_type, "jti": jti})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    return _create_token(
        data,
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "access",
    )


def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    """Generate a refresh JWT with a longer expiration."""
    return _create_token(data, expires_delta or timedelta(days=7), "refresh")


def decode_token(token: str) -> dict:
    """Decode a JWT, verify revocation, and return the payload."""
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise jwt.JWTError("Token revoked")
    return payload


def revoke_token(token: str) -> None:
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    exp = payload.get("exp")
    jti = payload.get("jti")
    if jti and exp:
        expires_in = int(exp - datetime.utcnow().timestamp())
        if expires_in > 0:
            add_token_to_blacklist(jti, expires_in)
