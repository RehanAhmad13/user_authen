# run.py
from app.database.session import engine, Base
from app.database.models import User, ActivityLog

Base.metadata.create_all(bind=engine)
