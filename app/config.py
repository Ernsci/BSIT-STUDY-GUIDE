import os

from dotenv import load_dotenv

load_dotenv()


def _get(name, default=""):
    return os.getenv(name, default)


SUPABASE_URL = _get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = _get("SUPABASE_SERVICE_KEY")
TELEGRAM_BOT_TOKEN = _get("TELEGRAM_BOT_TOKEN")
ADMIN_PASSWORD = _get("ADMIN_PASSWORD", "changeme")
ADMIN_SECRET = _get("ADMIN_SECRET", "changeme-secret")
APP_BASE_URL = _get("APP_BASE_URL", "http://localhost:8000")
TELEGRAM_POLLING = _get("TELEGRAM_POLLING", "0") == "1"
TELEGRAM_WEBHOOK_SECRET = _get("TELEGRAM_WEBHOOK_SECRET", "")

ORIGINALS_BUCKET = "originals"
PAGES_BUCKET = "pages"