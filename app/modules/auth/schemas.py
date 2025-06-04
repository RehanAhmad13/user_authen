from enum import Enum
from pydantic import BaseModel, EmailStr


class Role(str, Enum):
    user = "user"
    admin = "admin"


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Role = Role.user


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: Role
    is_active: bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
