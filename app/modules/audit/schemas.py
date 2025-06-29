from datetime import datetime
from pydantic import BaseModel


class ActivityLogOut(BaseModel):
    id: int
    user_id: int
    username: str
    action: str
    timestamp: str  # ISO string with formatted datetime

    class Config:
        orm_mode = True
