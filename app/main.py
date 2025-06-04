from fastapi import FastAPI
from app.modules.auth.routers import router as auth_router
from app.modules.users.routers import router as users_router
from app.modules.audit.routers import router as audit_router

app = FastAPI()

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(audit_router)
