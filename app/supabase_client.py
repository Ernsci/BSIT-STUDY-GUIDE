from supabase import create_client

from . import config

_client = None
if config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY:
    _client = create_client(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY)


def client():
    if _client is None:
        raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_KEY not configured")
    return _client