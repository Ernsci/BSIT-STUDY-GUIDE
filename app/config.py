import os

from dotenv import load_dotenv

load_dotenv()


def _get(name, default=""):
    return os.getenv(name, default)


SUPABASE_URL = _get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = _get("SUPABASE_SERVICE_KEY")
TELEGRAM_BOT_TOKEN = _get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = _get("TELEGRAM_CHAT_ID")
ADMIN_PASSWORD = _get("ADMIN_PASSWORD", "changeme")
ADMIN_SECRET = _get("ADMIN_SECRET", "changeme-secret")
ADMIN_URL_PATH = _get("ADMIN_URL_PATH", "shshs").strip("/")
ANTI_SPAM_MAX_PENDING = int(_get("ANTI_SPAM_MAX_PENDING", "2"))
ANTI_SPAM_MIN_SECONDS = int(_get("ANTI_SPAM_MIN_SECONDS", "60"))
APP_BASE_URL = _get("APP_BASE_URL", "http://localhost:8000")
TELEGRAM_POLLING = _get("TELEGRAM_POLLING", "0") == "1"
TELEGRAM_WEBHOOK_SECRET = _get("TELEGRAM_WEBHOOK_SECRET", "")

ORIGINALS_BUCKET = "originals"
PAGES_BUCKET = "pages"