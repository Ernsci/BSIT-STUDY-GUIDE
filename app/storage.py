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


def remove_original(path):
    client().storage.from_(config.ORIGINALS_BUCKET).remove([path])


def remove_pages(prefix):
    sb = client().storage.from_(config.PAGES_BUCKET)
    try:
        items = sb.list(prefix)
    except Exception:
        return
    paths = []
    for item in items or []:
        name = item.get("name")
        if not name:
            continue
        if item.get("id"):
            paths.append(f"{prefix}/{name}")
        else:
            sub = sb.list(f"{prefix}/{name}")
            for sub_item in sub or []:
                if sub_item.get("name"):
                    paths.append(f"{prefix}/{name}/{sub_item['name']}")
    if paths:
        sb.remove(paths)