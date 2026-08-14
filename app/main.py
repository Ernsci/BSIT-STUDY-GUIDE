import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel

from . import config, db, renderer, storage, telegram

STATIC_DIR = Path(__file__).parent / "static"
serializer = URLSafeSerializer(config.ADMIN_SECRET)

app = FastAPI(title="Approval Documents", docs_url=None, redoc_url=None)
app.mount("/pdfjs", StaticFiles(directory=STATIC_DIR / "pdfjs"), name="pdfjs")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


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
    return serializer.dumps({"uid": user_id})


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
    return user


def require_admin(admin_session: str = Cookie(default=None)):
    if not admin_session:
        raise HTTPException(status_code=401, detail="not logged in")
    try:
        serializer.loads(admin_session)
    except BadSignature:
        raise HTTPException(status_code=401, detail="bad session")
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
def register(body: RegisterBody):
    name = body.name.strip()[:120]
    email = body.email.strip().lower()[:200]
    password = body.password
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="valid email required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    if db.get_user_by_email(email):
        raise HTTPException(status_code=409, detail="email already registered")
    user = db.create_user(name, email, _hash_password(password))
    return {"token": _user_token(user["id"]), "name": user["name"], "email": user["email"]}


@app.post("/api/login")
def login(body: LoginBody):
    email = body.email.strip().lower()
    user = db.get_user_by_email(email)
    if not user or not _verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid email or password")
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
    """Groups incoming request notifications into a single Telegram message
    so a burst of traffic (5-10 people) doesn't flood the owner's chat."""

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
        by_chat = {}
        for it in items:
            by_chat.setdefault(it["chat_id"], []).append(it)
        for chat_id, group in by_chat.items():
            try:
                result = telegram.send_batch_requests(chat_id, group)
                if not result.get("ok"):
                    print(f"TELEGRAM SEND FAILED: {result.get('description')} chat_id={chat_id}")
            except Exception as exc:
                print(f"TELEGRAM SEND EXCEPTION: {exc} chat_id={chat_id}")


_batcher = _NotificationBatcher(config.REQUEST_BATCH_SECONDS, config.REQUEST_BATCH_MAX)


def _enqueue_notification(chat_id, kind, title, name, request_id, ip):
    _batcher.enqueue({
        "chat_id": chat_id,
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
def admin_login(response: Response, password: str = Form(...)):
    if password != config.ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="wrong password")
    response.set_cookie("admin_session", serializer.dumps({"sub": "admin"}), httponly=True, max_age=60 * 60 * 24 * 30)
    return {"ok": True}


@app.get("/api/admin/documents")
def admin_documents(_: bool = Depends(require_admin)):
    return db.list_documents()


@app.post("/api/admin/revoke/{doc_id}")
def admin_revoke(doc_id: int, _: bool = Depends(require_admin)):
    db.revoke_document(doc_id)
    return {"ok": True}


@app.post("/api/admin/delete/{doc_id}")
def admin_delete(doc_id: int, _: bool = Depends(require_admin)):
    doc = db.get_document(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="document not found")
    storage.remove_original(doc["original_path"])
    storage.remove_pages(doc["token"])
    db.delete_document(doc_id)
    return {"ok": True}


@app.post("/api/upload")
def upload_document(document: UploadFile = File(...), _: bool = Depends(require_admin)):
    if not (document.filename or "").lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only .pdf files are supported. Convert .docx locally first.")
    data = document.file.read()
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
    chat_id = config.TELEGRAM_CHAT_ID or db.get_owner_chat_id()
    if chat_id:
        _enqueue_notification(chat_id, "view", doc["title"], name, req["id"], client_ip or "")
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
    chat_id = config.TELEGRAM_CHAT_ID or db.get_owner_chat_id()
    if chat_id:
        _enqueue_notification(chat_id, "download", doc["title"], name, req["id"], client_ip or "")
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


def _process_approval(req, doc, chat_id, message_id, decided_by):
    try:
        original = storage.download_original(doc["original_path"])
        lines = ["BRION", f"Viewer: {req['visitor_name']}", _now()]
        pages = renderer.render_pdf(original, lines)
        pages_path = f"{doc['token']}/{req['id']}"
        for index, page_data in enumerate(pages, start=1):
            storage.upload_page(f"{pages_path}/{index}.jpg", page_data)
        view_pdf = renderer.render_pdf_to_pdf(original, lines)
        storage.upload_page(f"{pages_path}/view.pdf", view_pdf)
        db.set_request_status(req["id"], "approved", pages_path, decided_by=decided_by)
        telegram.edit_message(
            chat_id,
            message_id,
            telegram.format_decision(doc["title"], req["visitor_name"], req.get("ip"), "approve", decided_by),
            reply_markup={"inline_keyboard": []},
        )
    except Exception as exc:
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        telegram.edit_message(
            chat_id,
            message_id,
            telegram.format_decision(doc["title"], req["visitor_name"], req.get("ip"), "decline", decided_by),
            reply_markup={"inline_keyboard": []},
        )


def _process_download_approval(req, doc, chat_id, message_id, decided_by):
    try:
        original = storage.download_original(doc["original_path"])
        lines = ["BRION", f"Download: {req['visitor_name']}", _now()]
        view_pdf = renderer.render_pdf_to_pdf(original, lines)
        pages_path = f"{doc['token']}/{req['id']}"
        storage.upload_page(f"{pages_path}/view.pdf", view_pdf)
        db.set_request_status(req["id"], "approved", pages_path, decided_by=decided_by)
        telegram.edit_message(
            chat_id,
            message_id,
            telegram.format_decision(doc["title"], req["visitor_name"], req.get("ip"), "approve", decided_by, kind="download"),
            reply_markup={"inline_keyboard": []},
        )
    except Exception as exc:
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        telegram.edit_message(
            chat_id,
            message_id,
            telegram.format_decision(doc["title"], req["visitor_name"], req.get("ip"), "decline", decided_by, kind="download"),
            reply_markup={"inline_keyboard": []},
        )


def handle_update(update):
    message = update.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    text = (message.get("text") or "").strip()

    if text == "/start" and chat_id is not None:
        db.set_owner_chat_id(chat_id)
        telegram.send_text(chat_id, "Registered as approval destination. New access requests will appear here.")
    elif text == "/groupid" and chat_id is not None:
        telegram.send_text(chat_id, f"Chat ID: {chat_id}")

    callback = update.get("callback_query")
    if not callback:
        return
    data = callback.get("data", "")
    callback_chat_id = callback["message"]["chat"]["id"]
    message_id = callback["message"]["message_id"]
    action, _, rid = data.partition(":")
    req = db.get_access_request(int(rid)) if rid.isdigit() else None
    if not req:
        telegram.edit_message(callback_chat_id, message_id, "Request not found.")
        return
    doc = db.get_document(req["document_id"])
    user = callback.get("from") or {}
    decided_by = " ".join(filter(None, [user.get("first_name"), user.get("last_name")])) or user.get("username") or "Unknown"
    if action == "approve":
        telegram.answer_callback(callback["id"], "Approving...")
        threading.Thread(target=_process_approval, args=(req, doc, callback_chat_id, message_id, decided_by), daemon=True).start()
    elif action == "dapprove":
        telegram.answer_callback(callback["id"], "Preparing download...")
        threading.Thread(target=_process_download_approval, args=(req, doc, callback_chat_id, message_id, decided_by), daemon=True).start()
    elif action == "ddecline":
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        telegram.answer_callback(callback["id"], "Declined")
        telegram.edit_message(
            callback_chat_id,
            message_id,
            telegram.format_decision(doc["title"], req["visitor_name"], req.get("ip"), "decline", decided_by, kind="download"),
            reply_markup={"inline_keyboard": []},
        )
    else:
        db.set_request_status(req["id"], "declined", decided_by=decided_by)
        telegram.answer_callback(callback["id"], "Declined")
        telegram.edit_message(
            callback_chat_id,
            message_id,
            telegram.format_decision(doc["title"], req["visitor_name"], req.get("ip"), "decline", decided_by),
            reply_markup={"inline_keyboard": []},
        )


@app.post("/api/telegram/webhook")
async def telegram_webhook(request: Request):
    if config.TELEGRAM_WEBHOOK_SECRET:
        supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if supplied != config.TELEGRAM_WEBHOOK_SECRET:
            raise HTTPException(status_code=403, detail="invalid webhook secret")
    update = await request.json()
    handle_update(update)
    return {"ok": True}


def _polling_loop():
    offset = 0
    while True:
        try:
            updates = telegram.get_updates(offset=offset)
            for update in updates:
                handle_update(update)
                offset = update["update_id"] + 1
        except Exception:
            time.sleep(3)


@app.on_event("startup")
def startup():
    try:
        storage.ensure_buckets()
    except Exception:
        pass
    if config.TELEGRAM_POLLING:
        threading.Thread(target=_polling_loop, daemon=True).start()