import time
from app.core.config import settings

try:
    import redis  # type: ignore
    _client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    _client.ping()
    redis_client = _client
except Exception:  # pragma: no cover - fallback when redis unavailable
    redis_client = None
    _blacklist: dict[str, float] = {}


def add_token_to_blacklist(jti: str, expires_in: int) -> None:
    if redis_client:
        redis_client.setex(jti, expires_in, 1)
    else:
        _blacklist[jti] = time.time() + expires_in


def is_token_revoked(jti: str) -> bool:
    if redis_client:
        return redis_client.get(jti) is not None
    exp = _blacklist.get(jti)
    if exp is None:
        return False
    if exp < time.time():
        _blacklist.pop(jti, None)
        return False
    return True
