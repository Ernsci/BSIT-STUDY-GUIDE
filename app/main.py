import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel

from . import config, db, discord, renderer, storage

STATIC_DIR = Path(__file__).parent / "static"
serializer = URLSafeSerializer(config.ADMIN_SECRET)


class _RateLimiter:
    """In-memory sliding-window rate limiter keyed by (namespace, client_key)."""

    def __init__(self, max_attempts, window_seconds):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits = defaultdict(deque)

    def hit(self, key):
        """Record an attempt. Returns True if allowed, False if over the limit."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window_seconds:
                q.popleft()
            if len(q) >= self.max_attempts:
                return False
            q.append(now)
            return True

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)


_login_limiter = _RateLimiter(config.LOGIN_MAX_ATTEMPTS, config.LOGIN_LOCKOUT_SECONDS)
_admin_login_limiter = _RateLimiter(config.ADMIN_LOGIN_MAX_ATTEMPTS, config.ADMIN_LOGIN_LOCKOUT_SECONDS)


class _SessionRevoker:
    """In-memory denylist of signed session tokens invalidated by logout."""

    def __init__(self):
        self._lock = threading.Lock()
        self._revoked = set()

    def revoke(self, token):
        with self._lock:
            self._revoked.add(token)

    def is_revoked(self, token):
        with self._lock:
            if token in self._revoked:
                return True
            if len(self._revoked) > 500:
                self._revoked.clear()
            return False


_admin_sessions = _SessionRevoker()


def _client_ip(request: Request):
    return request.client.host if request.client else "unknown"


def _admin_session_token(request: Request):
    ip = _client_ip(request)
    ua = (request.headers.get("user-agent") or "")[:200]
    return serializer.dumps({
        "sub": "admin",
        "iat": time.time(),
        "ip": ip,
        "ua": ua,
    })


def _is_https(request: Request):
    fwd = request.headers.get("x-forwarded-proto", "")
    if fwd == "https":
        return True
    return (request.url.scheme == "https") or config.APP_BASE_URL.startswith("https")


def require_safe_origin(request: Request):
    if request.headers.get("x-requested-with"):
        return True
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    host = request.headers.get("host")
    if origin:
        try:
            o_host = urlparse(origin).netloc
        except Exception:
            o_host = ""
        if o_host != host:
            raise HTTPException(status_code=403, detail="cross-origin request blocked")
        return True
    if referer:
        try:
            r_host = urlparse(referer).netloc
        except Exception:
            r_host = ""
        if r_host != host:
            raise HTTPException(status_code=403, detail="cross-origin request blocked")
        return True
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        raise HTTPException(status_code=403, detail="missing origin header")
    return True

app = FastAPI(title="Approval Documents", docs_url=None, redoc_url=None)
app.mount("/pdfjs", StaticFiles(directory=STATIC_DIR / "pdfjs"), name="pdfjs")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def _hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${digest.hex()}"


def _verify_password(password, stored):
    try:
        salt, _, expected = stored.partition("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
        return hmac.compare_digest(digest.hex(), expected)
    except Exception:
        return False


def _user_token(user_id):
    return serializer.dumps({"uid": user_id, "iat": time.time()})


def _now():
    return datetime.now(timezone.utc).isoformat()


def _age_seconds(last_requested_at):
    if not last_requested_at:
        return None
    try:
        last = datetime.fromisoformat(last_requested_at)
    except Exception:
        return None
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last).total_seconds()


def require_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="not logged in")
    try:
        payload = serializer.loads(token)
    except BadSignature:
        raise HTTPException(status_code=401, detail="bad session")
    uid = payload.get("uid")
    user = db.get_user(uid) if isinstance(uid, int) else None
    if not user:
        raise HTTPException(status_code=401, detail="account not found")
    if payload.get("iat") is None or time.time() - payload["iat"] > config.ADMIN_SESSION_HOURS * 3600:
        raise HTTPException(status_code=401, detail="session expired")
    return user


def require_admin(admin_session: str = Cookie(default=None), request: Request = None):
    if not admin_session:
        raise HTTPException(status_code=401, detail="not logged in")
    if _admin_sessions.is_revoked(admin_session):
        raise HTTPException(status_code=401, detail="session invalid")
    try:
        payload = serializer.loads(admin_session)
    except BadSignature:
        raise HTTPException(status_code=401, detail="bad session")
    if payload.get("sub") != "admin":
        raise HTTPException(status_code=401, detail="bad session")
    if payload.get("iat") is None or time.time() - payload["iat"] > config.ADMIN_SESSION_HOURS * 3600:
        raise HTTPException(status_code=401, detail="session expired")
    if payload.get("ip") != _client_ip(request):
        raise HTTPException(status_code=401, detail="session invalid")
    if payload.get("ua") != (request.headers.get("user-agent") or "")[:200]:
        raise HTTPException(status_code=401, detail="session invalid")
    return True


class RequestBody(BaseModel):
    token: str


class RegisterBody(BaseModel):
    name: str
    email: str
    password: str


class LoginBody(BaseModel):
    email: str
    password: str


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/site")
def site_info():
    return {
        "site_name": "Documents for Nerds",
        "facebook_url": config.OWNER_FACEBOOK_URL,
        "owner_email": config.OWNER_EMAIL,
    }


@app.post("/api/register")
def register(body: RegisterBody, request: Request):
    if not _login_limiter.hit(f"register:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many accounts from this device. Try again later.")
    name = body.name.strip()[:120]
    email = body.email.strip().lower()[:200]
    password = body.password
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="valid email required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="password too long")
    if db.get_user_by_email(email):
        raise HTTPException(status_code=409, detail="email already registered")
    user = db.create_user(name, email, _hash_password(password))
    return {"token": _user_token(user["id"]), "name": user["name"], "email": user["email"]}


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    if not _login_limiter.hit(f"login:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    email = body.email.strip().lower()
    user = db.get_user_by_email(email)
    if not user or not _verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid email or password")
    _login_limiter.reset(f"login:{_client_ip(request)}")
    return {"token": _user_token(user["id"]), "name": user["name"], "email": user["email"]}


@app.get("/api/me")
def me(user: dict = Depends(require_user)):
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


@app.get("/", response_class=FileResponse)
def dashboard_page():
    return FileResponse(STATIC_DIR / "dashboard.html")


def _enforce_antispam(user_id):
    pending = db.count_pending_requests(user_id)
    if pending >= config.ANTI_SPAM_MAX_PENDING:
        raise HTTPException(status_code=429, detail="Too many pending requests. Wait for them to be decided.")
    last_at = db.last_request_at(user_id)
    age = _age_seconds(last_at)
    if age is not None and age < config.ANTI_SPAM_MIN_SECONDS:
        wait = int(config.ANTI_SPAM_MIN_SECONDS - age)
        raise HTTPException(status_code=429, detail=f"Please wait {wait}s before requesting again.")


class _NotificationBatcher:
    """Groups incoming request notifications into a single Discord embed
    so a burst of traffic (5-10 people) doesn't flood the owner's channel."""

    def __init__(self, flush_seconds, max_items):
        self.flush_seconds = flush_seconds
        self.max_items = max_items
        self._lock = threading.Lock()
        self._items = []
        self._timer = None

    def enqueue(self, item):
        with self._lock:
            self._items.append(item)
            if len(self._items) >= self.max_items:
                self._flush_locked()
            elif self._timer is None:
                self._timer = threading.Timer(self.flush_seconds, self._flush)
                self._timer.daemon = True
                self._timer.start()

    def _flush(self):
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        items, self._items = self._items, []
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if not items:
            return
        try:
            results = discord.send_request_embeds(items)
            for message_id, request_ids in results:
                if message_id:
                    db.set_request_batch_message(request_ids, message_id)
        except Exception as exc:
            print(f"DISCORD SEND EXCEPTION: {exc}")


_batcher = _NotificationBatcher(config.REQUEST_BATCH_SECONDS, config.REQUEST_BATCH_MAX)


def _enqueue_notification(kind, title, name, request_id, ip):
    _batcher.enqueue({
        "kind": kind,
        "title": title,
        "name": name,
        "request_id": request_id,
        "ip": ip,
    })


@app.get("/api/documents")
def public_documents():
    return db.list_active_documents()


@app.get("/docs", response_class=FileResponse)
def docs_page():
    return FileResponse(STATIC_DIR / "login-needed.html")


@app.get(f"/{config.ADMIN_URL_PATH}", response_class=FileResponse)
def admin_secret_page():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/v/{token}", response_class=FileResponse)
def viewer_page(token: str):
    doc = db.get_document_by_token(token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404, detail="link not found or revoked")
    return FileResponse(STATIC_DIR / "viewer.html")


@app.post("/api/admin/login")
def admin_login(response: Response, request: Request, password: str = Form(...)):
    if not _admin_login_limiter.hit(f"admin:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    if not hmac.compare_digest(password.encode(), config.ADMIN_PASSWORD.encode()):
        raise HTTPException(status_code=401, detail="wrong password")
    _admin_login_limiter.reset(f"admin:{_client_ip(request)}")
    response.set_cookie(
        "admin_session",
        _admin_session_token(request),
        httponly=True,
        secure=_is_https(request),
        samesite="lax",
        max_age=config.ADMIN_SESSION_HOURS * 3600,
    )
    return {"ok": True}


@app.post("/api/admin/logout")
def admin_logout(response: Response, request: Request, admin_session: str = Cookie(default=None)):
    if admin_session:
        _admin_sessions.revoke(admin_session)
    response.delete_cookie("admin_session")
    return {"ok": True}


@app.get("/api/admin/documents")
def admin_documents(_: bool = Depends(require_admin)):
    return db.list_documents()


@app.post("/api/admin/revoke/{doc_id}")
def admin_revoke(doc_id: int, _: bool = Depends(require_admin), __: bool = Depends(require_safe_origin)):
    db.revoke_document(doc_id)
    return {"ok": True}


@app.post("/api/admin/delete/{doc_id}")
def admin_delete(doc_id: int, _: bool = Depends(require_admin), __: bool = Depends(require_safe_origin)):
    doc = db.get_document(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="document not found")
    storage.remove_original(doc["original_path"])
    storage.remove_pages(doc["token"])
    db.delete_document(doc_id)
    return {"ok": True}


@app.post("/api/upload")
def upload_document(document: UploadFile = File(...), _: bool = Depends(require_admin), __: bool = Depends(require_safe_origin)):
    if not (document.filename or "").lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only .pdf files are supported. Convert .docx locally first.")
    data = document.file.read()
    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {config.MAX_UPLOAD_MB} MB limit.")
    if not data[:5] == b"%PDF-":
        raise HTTPException(status_code=400, detail="File is not a valid PDF.")
    title = Path(document.filename).stem
    token = secrets.token_urlsafe(9)
    pages = renderer.render_pdf(data, ["BRION", token, _now()])
    page_count = len(pages)
    original_path = f"{token}/original.pdf"
    storage.upload_original(original_path, data)
    row = db.create_document(token, title, original_path, page_count)
    return {"token": token, "id": row["id"], "url": f"/v/{token}"}


@app.post("/api/request")
def new_request(body: RequestBody, request: Request, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(body.token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404, detail="link not found or revoked")
    name = user["name"]
    client_ip = request.client.host if request.client else None
    _enforce_antispam(user["id"])
    req = db.create_access_request(doc["id"], name, ip=client_ip, user_id=user["id"])
    if config.DISCORD_WEBHOOK_URL:
        _enqueue_notification("view", doc["title"], name, req["id"], client_ip or "")
    return {"request_id": req["id"]}


@app.post("/api/download/request")
def new_download_request(body: RequestBody, request: Request, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(body.token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404, detail="link not found or revoked")
    name = user["name"]
    client_ip = request.client.host if request.client else None
    _enforce_antispam(user["id"])
    req = db.create_access_request(doc["id"], name, ip=client_ip, kind="download", user_id=user["id"])
    if config.DISCORD_WEBHOOK_URL:
        _enqueue_notification("download", doc["title"], name, req["id"], client_ip or "")
    return {"request_id": req["id"]}


@app.get("/api/download/status/{token}/{request_id}")
def download_status(token: str, request_id: int):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"]:
        raise HTTPException(status_code=404)
    return {
        "status": req["status"],
        "download_url": f"/v/{token}/download/{request_id}" if req["status"] == "approved" else None,
    }


@app.get("/v/{token}/download/{request_id}")
def serve_download(token: str, request_id: int, request: Request):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"] or req["status"] != "approved" or req.get("kind") != "download":
        raise HTTPException(status_code=403)
    if not req.get("pages_path"):
        raise HTTPException(status_code=404)
    path = f"{req['pages_path']}/view.pdf"
    data = storage.download_page(path)
    try:
        db.log_view(request_id, 0, request.client.host if request.client else None, request.headers.get("user-agent"))
    except Exception:
        pass
    filename = f"{Path(doc['title']).stem}.pdf"
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/my/documents")
def my_documents(user: dict = Depends(require_user)):
    docs = db.list_active_documents()
    requests = db.get_user_requests(user["id"])
    by_doc = {}
    for r in requests:
        entry = by_doc.setdefault(r["document_id"], {"view": None, "download": None})
        if r["kind"] == "view" and entry["view"] is None:
            entry["view"] = r
        elif r["kind"] == "download" and entry["download"] is None:
            entry["download"] = r
    result = []
    for d in docs:
        r = by_doc.get(d["id"], {"view": None, "download": None})
        view, dl = r["view"], r["download"]
        result.append({
            "id": d["id"],
            "token": d["token"],
            "title": d["title"],
            "page_count": d["page_count"],
            "view": {
                "status": view["status"] if view else "none",
                "request_id": view["id"] if view else None,
                "pdf": f"/v/{d['token']}/pdf/{view['id']}" if view and view["status"] == "approved" else None,
            },
            "download": {
                "status": dl["status"] if dl else "none",
                "request_id": dl["id"] if dl else None,
                "url": f"/v/{d['token']}/download/{dl['id']}" if dl and dl["status"] == "approved" else None,
            },
        })
    return result


@app.get("/api/my/status/{token}")
def my_status(token: str, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404, detail="link not found or revoked")
    view = db.get_latest_request(doc["id"], user["id"], "view", "approved")
    dl = db.get_latest_request(doc["id"], user["id"], "download", "approved")
    pending_view = db.get_latest_request(doc["id"], user["id"], "view", "pending")
    pending_dl = db.get_latest_request(doc["id"], user["id"], "download", "pending")
    return {
        "view_approved": bool(view),
        "view_pdf": f"/v/{token}/pdf/{view['id']}" if view else None,
        "download_approved": bool(dl),
        "download_url": f"/v/{token}/download/{dl['id']}" if dl else None,
        "pending_view": pending_view["id"] if pending_view else None,
        "pending_download": pending_dl["id"] if pending_dl else None,
    }


@app.get("/api/status/{token}/{request_id}")
def request_status(token: str, request_id: int):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"]:
        raise HTTPException(status_code=404)
    pages = []
    if req["status"] == "approved" and req.get("pages_path"):
        pages = [f"/v/{token}/page/{request_id}/{n}" for n in range(1, doc["page_count"] + 1)]
    return {"status": req["status"], "pages": pages, "pdf": f"/v/{token}/pdf/{request_id}" if req["status"] == "approved" else None}


@app.get("/v/{token}/page/{request_id}/{page_number}")
def serve_page(token: str, request_id: int, page_number: int, request: Request):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"] or req["status"] != "approved":
        raise HTTPException(status_code=403)
    if page_number < 1 or page_number > doc["page_count"]:
        raise HTTPException(status_code=404)
    path = f"{req['pages_path']}/{page_number}.jpg"
    data = storage.download_page(path)
    try:
        db.log_view(request_id, page_number, request.client.host if request.client else None, request.headers.get("user-agent"))
    except Exception:
        pass
    return Response(content=data, media_type="image/jpeg")


@app.get("/v/{token}/pdf/{request_id}")
def serve_pdf(token: str, request_id: int, request: Request):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"] or req["status"] != "approved":
        raise HTTPException(status_code=403)
    path = f"{req['pages_path']}/view.pdf"
    data = storage.download_page(path)
    try:
        db.log_view(request_id, 0, request.client.host if request.client else None, request.headers.get("user-agent"))
    except Exception:
        pass
    return Response(content=data, media_type="application/pdf")


def _process_approval(req, doc, edit_spec, decided_by):
    try:
        original = storage.download_original(doc["original_path"])
        lines = ["BRION", f"Viewer: {req['visitor_name']}", _now()]
        pages, view_pdf = renderer.render_pdf_with_pdf(
            original, lines, scale=config.RENDER_SCALE, quality=config.RENDER_QUALITY
        )
        pages_path = f"{doc['token']}/{req['id']}"
        for index, page_data in enumerate(pages, start=1):
            storage.upload_page(f"{pages_path}/{index}.jpg", page_data)
        storage.upload_page(f"{pages_path}/view.pdf", view_pdf)
        db.set_request_status(req["id"], "approved", pages_path, decided_by=decided_by)
        _finalize_message(edit_spec, req, doc, "approve", decided_by)
    except Exception as exc:
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        _finalize_message(edit_spec, req, doc, "decline", decided_by)


def _process_download_approval(req, doc, edit_spec, decided_by):
    try:
        original = storage.download_original(doc["original_path"])
        lines = ["BRION", f"Download: {req['visitor_name']}", _now()]
        _, view_pdf = renderer.render_pdf_with_pdf(
            original, lines, scale=config.RENDER_SCALE, quality=config.RENDER_QUALITY
        )
        pages_path = f"{doc['token']}/{req['id']}"
        storage.upload_page(f"{pages_path}/view.pdf", view_pdf)
        db.set_request_status(req["id"], "approved", pages_path, decided_by=decided_by)
        _finalize_message(edit_spec, req, doc, "approve", decided_by, kind="download")
    except Exception as exc:
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        _finalize_message(edit_spec, req, doc, "decline", decided_by, kind="download")


def _rebuild_batch_message(edit_spec):
    """Re-render a grouped notification message from current DB state.
    Decided requests become plain embeds; still-pending ones keep their buttons."""
    message_id = edit_spec.get("message_id")
    if not message_id:
        return False
    reqs = db.get_requests_by_batch(message_id)
    if not reqs:
        return False
    embeds, components = discord.build_batch_embeds_and_components(reqs)
    discord.edit_message(edit_spec, embeds, components)
    return True


def _finalize_message(edit_spec, req, doc, action, decided_by, kind="view"):
    """After a decision, rebuild the batch if this request was part of one,
    otherwise replace with the single-request decision embed."""
    try:
        if _rebuild_batch_message(edit_spec):
            return
    except Exception:
        pass
    discord.edit_message(edit_spec, [discord.decision_embed(doc, req, action, decided_by, kind=kind)], [])


def _process_decline(req, doc, edit_spec, decided_by, kind="view"):
    try:
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        _finalize_message(edit_spec, req, doc, "decline", decided_by, kind=kind)
    except Exception:
        pass


def _handle_discord_component(interaction, edit_spec):
    data = interaction.get("data") or {}
    custom_id = data.get("custom_id") or ""
    user = (interaction.get("member") or {}).get("user") or interaction.get("user") or {}
    decided_by = (
        user.get("global_name")
        or user.get("username")
        or " ".join(filter(None, [user.get("first_name"), user.get("last_name")]))
        or "Unknown"
    )
    action, _, rid = custom_id.partition(":")
    req = db.get_access_request(int(rid)) if rid.isdigit() else None
    if not req:
        return
    doc = db.get_document(req["document_id"])
    if action == "approve":
        threading.Thread(target=_process_approval, args=(req, doc, edit_spec, decided_by), daemon=True).start()
    elif action == "dapprove":
        threading.Thread(target=_process_download_approval, args=(req, doc, edit_spec, decided_by), daemon=True).start()
    elif action == "ddecline":
        threading.Thread(
            target=_process_decline, args=(req, doc, edit_spec, decided_by, "download"), daemon=True
        ).start()
    else:
        threading.Thread(target=_process_decline, args=(req, doc, edit_spec, decided_by), daemon=True).start()


@app.post("/api/discord/interactions")
async def discord_interactions(request: Request):
    raw_body = await request.body()
    signature = request.headers.get("X-Signature-Ed25519", "")
    timestamp = request.headers.get("X-Signature-Timestamp", "")
    if not config.DISCORD_PUBLIC_KEY:
        print("DISCORD: DISCORD_PUBLIC_KEY is not set — Discord endpoint verification will fail.")
    if not discord.verify_signature(raw_body, signature, timestamp):
        print(f"DISCORD: signature verification FAILED (pubkey set: {bool(config.DISCORD_PUBLIC_KEY)})")
        raise HTTPException(status_code=401, detail="invalid signature")
    payload = json.loads(raw_body)
    if payload.get("type") == 1:
        return {"type": 1}
    if payload.get("type") == 3:
        edit_spec = {
            "app_id": config.DISCORD_APPLICATION_ID,
            "interaction_token": payload.get("token"),
            "message_id": (payload.get("message") or {}).get("id"),
        }
        _handle_discord_component(payload, edit_spec)
    return {"type": 6, "data": {"flags": 64}}


@app.on_event("startup")
def startup():
    try:
        storage.ensure_buckets()
    except Exception:
        pass