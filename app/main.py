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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
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
_guide_limiter = _RateLimiter(config.GUIDE_REQUEST_MAX, config.GUIDE_REQUEST_WINDOW_SECONDS)


class _SessionRevoker:
    """In-memory denylist of signed session tokens invalidated by logout."""

    def __init__(self):
        self._lock = threading.Lock()
        self._revoked = {}

    def revoke(self, token):
        with self._lock:
            self._revoked[token] = time.time()

    def is_revoked(self, token):
        with self._lock:
            self._prune()
            return token in self._revoked

    def _prune(self):
        cutoff = time.time() - config.ADMIN_SESSION_HOURS * 3600
        stale = [t for t, ts in self._revoked.items() if ts < cutoff]
        for t in stale:
            self._revoked.pop(t, None)


_admin_sessions = _SessionRevoker()


class _ResetCodeStore:
    """In-memory one-time reset codes: code -> {email, expires}."""

    def __init__(self):
        self._lock = threading.Lock()
        self._codes = {}

    def put(self, code, email, ttl_seconds):
        with self._lock:
            self._prune_locked()
            self._codes[code] = {"email": email, "expires": time.time() + ttl_seconds}

    def pop(self, code):
        with self._lock:
            self._prune_locked()
            entry = self._codes.pop(code, None)
            if entry is None:
                return None
            if entry["expires"] < time.time():
                return None
            return entry

    def _prune_locked(self):
        now = time.time()
        stale = [c for c, e in self._codes.items() if e["expires"] < now]
        for c in stale:
            self._codes.pop(c, None)


_reset_codes = _ResetCodeStore()


def _client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
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


@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.url.path.startswith("/v/"):
        accept = request.headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept:
            parts = request.url.path.split("/")
            if len(parts) >= 3 and parts[1] == "v" and parts[2]:
                return RedirectResponse(url=f"/v/{parts[2]}", status_code=302)
            return RedirectResponse(url="/", status_code=302)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


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


class GoogleBody(BaseModel):
    access_token: str


class ForgotBody(BaseModel):
    email: str


class ResetBody(BaseModel):
    token: str
    password: str


class ChangePasswordBody(BaseModel):
    current: str
    new: str


class ResetCodeBody(BaseModel):
    code: str


class GuideRequestBody(BaseModel):
    title: str
    note: str = ""


class AdminModeBody(BaseModel):
    mode: str


GOOGLE_ONLY_HASH = "!google-only!"


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/site")
def site_info():
    return {
        "site_name": "Documents for Nerds",
        "facebook_url": config.OWNER_FACEBOOK_URL,
        "owner_email": config.OWNER_EMAIL,
        "supabase_url": config.SUPABASE_URL or None,
        "supabase_anon_key": config.SUPABASE_ANON_KEY or None,
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
    if not user:
        raise HTTPException(status_code=401, detail="invalid email or password")
    if user["password_hash"] == GOOGLE_ONLY_HASH:
        raise HTTPException(
            status_code=403,
            detail="This email is linked to a Google account. Please log in with the Google button instead.",
        )
    if not _verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid email or password")
    _login_limiter.reset(f"login:{_client_ip(request)}")
    return {"token": _user_token(user["id"]), "name": user["name"], "email": user["email"]}


@app.get("/api/me")
def me(user: dict = Depends(require_user)):
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


def _supabase_userinfo(access_token):
    """Validate a Supabase Auth access token by calling the /auth/v1/user endpoint."""
    import requests

    if not config.SUPABASE_URL or not config.SUPABASE_ANON_KEY:
        raise HTTPException(status_code=503, detail="Google sign-in is not enabled.")
    try:
        resp = requests.get(
            f"{config.SUPABASE_URL}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "apikey": config.SUPABASE_ANON_KEY,
            },
            timeout=10,
        )
    except Exception:
        raise HTTPException(status_code=503, detail="Could not reach the auth provider.")
    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="invalid or expired Google session")
    info = resp.json()
    email = (info.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=401, detail="Google account has no email")
    name = (info.get("user_metadata") or {}).get("full_name") or email.split("@")[0]
    return {
        "email": email,
        "name": str(name).strip()[:120],
    }


@app.post("/api/google")
def google_login(body: GoogleBody):
    info = _supabase_userinfo(body.access_token)
    user = db.get_user_by_email(info["email"])
    if not user:
        if not info["name"]:
            raise HTTPException(status_code=400, detail="Google account has no name")
        user = db.create_user(info["name"], info["email"], GOOGLE_ONLY_HASH)
    return {"token": _user_token(user["id"]), "name": user["name"], "email": user["email"]}


def _make_reset_token(email):
    return serializer.dumps({"sub": "password-reset", "email": email, "iat": time.time()})


def _verify_reset_token(token):
    try:
        payload = serializer.loads(token)
    except BadSignature:
        raise HTTPException(status_code=400, detail="invalid reset link")
    if payload.get("sub") != "password-reset" or not payload.get("email"):
        raise HTTPException(status_code=400, detail="invalid reset link")
    if payload.get("iat") is None or time.time() - payload["iat"] > config.PASSWORD_RESET_HOURS * 3600:
        raise HTTPException(status_code=400, detail="reset link expired")
    return payload["email"]


@app.post("/api/forgot")
def forgot_password(body: ForgotBody, request: Request):
    if not _login_limiter.hit(f"forgot:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    email = body.email.strip().lower()[:200]
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="valid email required")
    user = db.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="no account found for that email")
    if user["password_hash"] == GOOGLE_ONLY_HASH:
        raise HTTPException(status_code=400, detail="this email uses Google sign-in")
    code = secrets.token_hex(4).upper()
    _reset_codes.put(code, email, config.PASSWORD_RESET_HOURS * 3600)
    return {
        "code": code,
        "expires_hours": config.PASSWORD_RESET_HOURS,
        "hint": "Send this code to the site owner, who can give you a reset link.",
    }


@app.post("/api/reset")
def reset_password(body: ResetBody, request: Request):
    if not _login_limiter.hit(f"reset:{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    email = _verify_reset_token(body.token)
    if not _reset_codes.pop(body.token):
        raise HTTPException(status_code=400, detail="reset link already used or expired")
    password = body.password
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="password too long")
    user = db.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="account not found")
    db.update_user_password(user["id"], _hash_password(password))
    return {"ok": True}


@app.post("/api/change-password")
def change_password(body: ChangePasswordBody, user: dict = Depends(require_user)):
    stored = user.get("password_hash")
    if stored == GOOGLE_ONLY_HASH:
        raise HTTPException(status_code=400, detail="this account uses Google sign-in")
    if not _verify_password(body.current, stored):
        raise HTTPException(status_code=401, detail="current password incorrect")
    if len(body.new) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    if len(body.new) > 128:
        raise HTTPException(status_code=400, detail="password too long")
    db.update_user_password(user["id"], _hash_password(body.new))
    return {"ok": True}


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


@app.get("/reset/{token}", response_class=FileResponse)
def reset_page(token: str):
    try:
        serializer.loads(token)
    except BadSignature:
        raise HTTPException(status_code=404, detail="invalid reset link")
    return FileResponse(STATIC_DIR / "reset.html")


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


@app.post("/api/admin/reset-link")
def admin_reset_link(
    body: ResetCodeBody,
    _: bool = Depends(require_admin),
    __: bool = Depends(require_safe_origin),
):
    entry = _reset_codes.pop(body.code.strip().upper())
    if not entry:
        raise HTTPException(status_code=400, detail="invalid or expired code")
    token = _make_reset_token(entry["email"])
    _reset_codes.put(token, entry["email"], config.PASSWORD_RESET_HOURS * 3600)
    return {
        "email": entry["email"],
        "url": f"{config.APP_BASE_URL}/reset/{token}",
    }


@app.post("/api/admin/revoke/{doc_id}")
def admin_revoke(doc_id: int, _: bool = Depends(require_admin), __: bool = Depends(require_safe_origin)):
    db.revoke_document(doc_id)
    return {"ok": True}


@app.post("/api/admin/mode/{doc_id}")
def admin_mode(
    doc_id: int,
    body: AdminModeBody,
    _: bool = Depends(require_admin),
    __: bool = Depends(require_safe_origin),
):
    mode = body.mode.strip().lower()
    if mode not in ("open", "restricted"):
        raise HTTPException(status_code=400, detail="mode must be 'open' or 'restricted'")
    db.set_document_mode(doc_id, mode)
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
    client_ip = _client_ip(request)
    is_open = (doc.get("access_mode") or "restricted") == "open"
    if not is_open:
        _enforce_antispam(user["id"])
    req = db.create_access_request(doc["id"], name, ip=client_ip, user_id=user["id"])
    if is_open:
        threading.Thread(
            target=_process_approval, args=(req, doc, None, "System (auto)"), daemon=True
        ).start()
    elif discord.is_configured():
        _enqueue_notification("view", doc["title"], name, req["id"], client_ip or "")
    return {"request_id": req["id"]}


@app.post("/api/download/request")
def new_download_request(body: RequestBody, request: Request, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(body.token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404, detail="link not found or revoked")
    name = user["name"]
    client_ip = _client_ip(request)
    is_open = (doc.get("access_mode") or "restricted") == "open"
    if not is_open:
        _enforce_antispam(user["id"])
    req = db.create_access_request(doc["id"], name, ip=client_ip, kind="download", user_id=user["id"])
    if is_open:
        threading.Thread(
            target=_process_download_approval, args=(req, doc, None, "System (auto)"), daemon=True
        ).start()
    elif discord.is_configured():
        _enqueue_notification("download", doc["title"], name, req["id"], client_ip or "")
    return {"request_id": req["id"]}


@app.post("/api/guide/request")
def new_guide_request(body: GuideRequestBody, user: dict = Depends(require_user)):
    title = body.title.strip()
    note = body.note.strip()
    if not title:
        raise HTTPException(status_code=400, detail="topic is required")
    if len(title) > config.GUIDE_TITLE_MAX:
        raise HTTPException(status_code=400, detail=f"topic too long (max {config.GUIDE_TITLE_MAX} characters)")
    if len(note) > config.GUIDE_NOTE_MAX:
        raise HTTPException(status_code=400, detail=f"note too long (max {config.GUIDE_NOTE_MAX} characters)")
    if not _guide_limiter.hit(f"guide:{user['id']}"):
        wait = config.GUIDE_REQUEST_WINDOW_SECONDS // 60
        raise HTTPException(status_code=429, detail=f"Please wait {wait} minutes before requesting another study guide.")
    row = db.create_guide_request(user["id"], title, note)
    if discord.is_configured():
        try:
            discord.send_guide_request(user["name"], title, note, row["id"])
        except Exception as exc:
            print(f"DISCORD GUIDE SEND FAILED: {exc}")
    return {"ok": True, "guide_id": row["id"]}


@app.get("/api/guide/my")
def my_guide_requests(user: dict = Depends(require_user)):
    return db.get_user_guide_requests(user["id"])


@app.get("/api/download/status/{token}/{request_id}")
def download_status(token: str, request_id: int, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"]:
        raise HTTPException(status_code=404)
    if req.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="access denied")
    return {
        "status": req["status"],
        "download_url": f"/v/{token}/download/{request_id}" if req["status"] == "approved" else None,
    }


@app.get("/v/{token}/download/{request_id}")
def serve_download(token: str, request_id: int, request: Request, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"] or req["status"] != "approved" or req.get("kind") != "download":
        raise HTTPException(status_code=403)
    if req.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="access denied")
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
        if r["kind"] == "view":
            if entry["view"] is None or (entry["view"]["status"] != "approved" and r["status"] == "approved"):
                entry["view"] = r
        elif r["kind"] == "download":
            if entry["download"] is None or (entry["download"]["status"] != "approved" and r["status"] == "approved"):
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
            "access_mode": d.get("access_mode") or "restricted",
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
        "open_access": (doc.get("access_mode") or "restricted") == "open",
        "title": doc["title"],
    }


@app.get("/api/status/{token}/{request_id}")
def request_status(token: str, request_id: int, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(token)
    if not doc:
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"]:
        raise HTTPException(status_code=404)
    if req.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="access denied")
    pages = []
    if req["status"] == "approved" and req.get("pages_path"):
        pages = [f"/v/{token}/page/{request_id}/{n}" for n in range(1, doc["page_count"] + 1)]
    return {"status": req["status"], "pages": pages, "pdf": f"/v/{token}/pdf/{request_id}" if req["status"] == "approved" else None}


@app.get("/v/{token}/page/{request_id}/{page_number}")
def serve_page(token: str, request_id: int, page_number: int, request: Request, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"] or req["status"] != "approved":
        raise HTTPException(status_code=403)
    if req.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="access denied")
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
def serve_pdf(token: str, request_id: int, request: Request, user: dict = Depends(require_user)):
    doc = db.get_document_by_token(token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404)
    req = db.get_access_request(request_id)
    if not req or req["document_id"] != doc["id"] or req["status"] != "approved":
        raise HTTPException(status_code=403)
    if req.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="access denied")
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
        print(f"APPROVAL FAILED (req {req['id']}): {type(exc).__name__}: {exc}")
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
        print(f"DOWNLOAD APPROVAL FAILED (req {req['id']}): {type(exc).__name__}: {exc}")
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
    if not edit_spec:
        return
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
    except Exception as exc:
        print(f"DECLINE FAILED (req {req['id']}): {type(exc).__name__}: {exc}")


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
    if custom_id.startswith("guidecreated:"):
        _handle_guide_created(custom_id.split(":", 1)[1], decided_by, edit_spec)
        return
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


def _handle_guide_created(guide_id, created_by, edit_spec):
    """Mark a user study-guide request as created and refresh its Discord embed."""
    def run():
        try:
            row = db.get_guide_request(int(guide_id))
            if not row:
                return
            db.set_guide_request_status(row["id"], "created")
            user_info = db.get_user(row.get("user_id")) if row.get("user_id") else None
            name = (user_info or {}).get("name") or "A user"
            embed = discord.guide_request_embed(name, row["title"], row.get("note") or "", row["id"], created_by=created_by)
            discord.edit_message(edit_spec, [embed], [])
        except Exception as exc:
            print(f"GUIDE CREATED FAILED: {exc}")

    threading.Thread(target=run, daemon=True).start()


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