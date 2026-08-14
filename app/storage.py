from . import config
from .supabase_client import client


def ensure_buckets():
    sb = client().storage
    for bucket in (config.ORIGINALS_BUCKET, config.PAGES_BUCKET):
        try:
            sb.get_bucket(bucket)
        except Exception:
            sb.create_bucket(bucket, options={"public": False})


def upload_original(path, data):
    client().storage.from_(config.ORIGINALS_BUCKET).upload(path, data, {"content-type": "application/pdf"})


def download_original(path):
    return client().storage.from_(config.ORIGINALS_BUCKET).download(path)


def upload_page(path, data):
    client().storage.from_(config.PAGES_BUCKET).upload(path, data, {"content-type": "image/jpeg"})


def download_page(path):
    return client().storage.from_(config.PAGES_BUCKET).download(path)