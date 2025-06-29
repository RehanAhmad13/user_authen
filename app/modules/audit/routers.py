from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.dependencies import get_db, get_current_user
from app.modules.audit import repository
from app.modules.audit.schemas import ActivityLogOut
from app.database.models import User

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/users/{user_id}", response_model=List[ActivityLogOut])
def get_user_logs(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view these logs",
        )
    return repository.get_logs_for_user(db, user_id)
