# run.py
from app.database.session import engine, Base
from app.database.models import User, ActivityLog
from app.database.session import SessionLocal
from app.core.security import hash_password


Base.metadata.create_all(bind=engine)


db = SessionLocal()
if not db.query(User).filter_by(email="admin@example.com").first():
    admin = User(
        username="admin",
        email="admin@example.com",
        hashed_password=hash_password("AdminPass123!"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db.add(admin)
    db.commit()
    print("Admin user created: admin@example.com / AdminPass123!")
else:
    print("Admin user already exists.")
db.close()

from app.database.session import SessionLocal
from app.database.models import User

db = SessionLocal()
user = db.query(User).filter_by(email="admin@example.com").first()
print("Email:", user.email)
print("Role:", user.role)
print("Is verified:", user.is_verified)
print("Is active:", user.is_active)
print("Hashed password:", user.hashed_password)
db.close()
