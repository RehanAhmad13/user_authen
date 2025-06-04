from fastapi import FastAPI
from .config import settings
from .security import hash_password


def startup_event(app: FastAPI) -> None:
    """Placeholder startup event."""
    pass


def shutdown_event(app: FastAPI) -> None:
    """Placeholder shutdown event."""
    pass
