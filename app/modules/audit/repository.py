from typing import List
from sqlalchemy.orm import Session
from app.database.models import ActivityLog


def create_log(db: Session, user_id: int, action: str) -> ActivityLog:
    log = ActivityLog(user_id=user_id, action=action)
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_logs_for_user(db: Session, user_id: int) -> List[ActivityLog]:
    return (
        db.query(ActivityLog)
        .filter(ActivityLog.user_id == user_id)
        .order_by(ActivityLog.timestamp.desc())
        .all()
    )
