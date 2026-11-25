import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)


class ConfigurationError(RuntimeError):
    pass


def env_flag(name: str) -> bool:
    value = os.getenv(name, "false").strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off", ""):
        return False
    raise ConfigurationError(f"{name} must be true or false.")


if any(env_flag(name) for name in ("ALLOW_UNSAFE_DEV_AUTH", "DEBUG", "FLASK_DEBUG")):
    raise ConfigurationError("Disable ALLOW_UNSAFE_DEV_AUTH, DEBUG and FLASK_DEBUG.")

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
if SERVER_HOST not in ("127.0.0.1", "::1"):
    raise ConfigurationError("SERVER_HOST must be a loopback address.")
try:
    SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
except ValueError:
    raise ConfigurationError("SERVER_PORT must be a valid port.") from None
if not 1 <= SERVER_PORT <= 65535:
    raise ConfigurationError("SERVER_PORT must be a valid port.")

TRUST_PROXY_HEADERS = env_flag("TRUST_PROXY_HEADERS")
TRUSTED_HOSTS = tuple(
    host.strip() for host in os.getenv("TRUSTED_HOSTS", "").split(",") if host.strip()
)
MAX_FORM_BODY_BYTES = 65_536
try:
    ACTIVE_FORMS_RETENTION_DAYS = int(os.getenv("ACTIVE_FORMS_RETENTION_DAYS", "0"))
except ValueError:
    raise ConfigurationError("ACTIVE_FORMS_RETENTION_DAYS must be an integer.") from None
if not 0 <= ACTIVE_FORMS_RETENTION_DAYS <= 3650:
    raise ConfigurationError("ACTIVE_FORMS_RETENTION_DAYS must be between 0 and 3650.")

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_APP_URL = os.getenv("WEB_APP_URL", "")
FORM_SIGNING_KEY = os.getenv("FORM_SIGNING_KEY", os.getenv("FLASK_SECRET_KEY", ""))

database_path = os.getenv("DATABASE_PATH")
if not database_path and (BASE_DIR / "forms.db").exists():
    raise ConfigurationError("Set DATABASE_PATH to the existing database before starting.")
DATABASE_PATH = str(BASE_DIR / (database_path or "var/forms.db"))


def require_secret() -> str:
    if (
        len(FORM_SIGNING_KEY.encode()) < 32
        or not FORM_SIGNING_KEY.strip()
        or FORM_SIGNING_KEY == "forms-tgbot-secret-key-change-me"
    ):
        raise ConfigurationError("FORM_SIGNING_KEY must be at least 32 bytes. Generate a random key.")
    return FORM_SIGNING_KEY


def require_bot_token() -> str:
    if not re.fullmatch(r"[1-9][0-9]{0,15}:[A-Za-z0-9_-]{16,128}", BOT_TOKEN):
        raise ConfigurationError("Set BOT_TOKEN to a valid Telegram bot token.")
    return BOT_TOKEN


def parse_user_id(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]{0,15}", value):
        raise ValueError("Invalid Telegram user ID.")
    user_id = int(value)
    if user_id >= 2**52:
        raise ValueError("Invalid Telegram user ID.")
    return user_id


def require_web_app_url() -> str:
    try:
        parts = urlsplit(WEB_APP_URL)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or any(char.isspace() or ord(char) < 32 or char == "\\" for char in WEB_APP_URL)
        ):
            raise ValueError
        parts.port
    except ValueError:
        raise ConfigurationError("Set WEB_APP_URL to the public HTTPS address of the Mini App.") from None
    return WEB_APP_URL
