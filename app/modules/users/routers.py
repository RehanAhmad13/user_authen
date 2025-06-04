from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.dependencies import get_db, require_admin
from app.modules.auth.schemas import UserOut
from app.database.models import User
from app.modules.auth import repository

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/", response_model=List[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return repository.list_users(db)
