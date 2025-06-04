import re
from fastapi import HTTPException

ALLOWED_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com"}


def validate_username(username: str) -> None:
    if not isinstance(username, str):
        raise HTTPException(status_code=400, detail="Username must be a string.")
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long.")
    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        raise HTTPException(status_code=400, detail="Username can contain only letters, numbers, and underscores.")


def validate_email(email: str) -> None:
    if not isinstance(email, str):
        raise HTTPException(status_code=400, detail="Email must be a string.")
    parts = email.split("@")
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Email must be a valid email address.")
    local_part, domain = parts
    if domain != domain.lower():
        raise HTTPException(status_code=400, detail="Email domain must be lowercase (e.g., gmail.com).")
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=400, detail="Email domain must be one of: gmail.com, yahoo.com, or outlook.com.")
    if not re.fullmatch(r"[A-Za-z0-9._%+-]+", local_part):
        raise HTTPException(status_code=400, detail="Email must be a valid email address.")


def validate_password(password: str) -> None:
    if not isinstance(password, str):
        raise HTTPException(status_code=400, detail="Password must be a string.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character.")
