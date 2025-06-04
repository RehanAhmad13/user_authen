from typing import Tuple
from social_core.backends.google import GoogleOAuth2
from social_core.backends.facebook import FacebookOAuth2
from social_core.strategy import BaseStrategy
from app.core.config import settings


class SimpleStrategy(BaseStrategy):
    def __init__(self, data: dict):
        super().__init__()
        self._data = data

    # Required methods
    def request_data(self, merge=True):
        return self._data

    def get_setting(self, name):
        return getattr(settings, name)

    def build_absolute_uri(self, path=None):
        return path or ""

    # Unused interface methods
    def request_host(self):
        return ""

    def request_is_secure(self):
        return True

    def request_path(self):
        return ""

    def request_port(self):
        return ""

    def request_get(self):
        return self._data

    def request_post(self):
        return self._data

    def redirect(self, url):
        raise NotImplementedError

    def html(self, content):
        raise NotImplementedError

    def session_get(self, name, default=None):
        return default

    def session_set(self, name, value):
        pass

    def session_pop(self, name):
        pass


def fetch_google_user(code: str) -> Tuple[str, str]:
    strategy = SimpleStrategy({"code": code})
    backend = GoogleOAuth2(strategy=strategy, redirect_uri="")
    token = backend.request_access_token(
        backend.access_token_url(), data=backend.auth_complete_params()
    )["access_token"]
    data = backend.user_data(token)
    return data["email"], data.get("email", "").split("@")[0]


def fetch_facebook_user(code: str) -> Tuple[str, str]:
    strategy = SimpleStrategy({"code": code})
    backend = FacebookOAuth2(strategy=strategy, redirect_uri="")
    token = backend.request_access_token(
        backend.access_token_url(), data=backend.auth_complete_params()
    )["access_token"]
    data = backend.user_data(token)
    username = data.get("name") or data.get("email", "").split("@")[0]
    return data.get("email", ""), username

