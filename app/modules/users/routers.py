from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.dependencies import get_db, require_admin, get_current_user
from app.modules.auth.schemas import UserOut
from app.database.models import User
from app.modules.auth import repository
from app.modules.audit.repository import get_logs_for_user
from app.modules.audit.schemas import ActivityLogOut
from datetime import timezone

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/", response_model=List[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return repository.list_users(db)



@router.get("/{user_id}/logs", response_model=List[ActivityLogOut])
def user_logs(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    logs = get_logs_for_user(db, user_id)

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "username": user.username,
            "action": log.action,
            "timestamp": log.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %I:%M %p")
        }
        for log in logs
    ]
