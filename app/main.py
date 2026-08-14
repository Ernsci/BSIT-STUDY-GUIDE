import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel

from . import config, db, renderer, storage, telegram

STATIC_DIR = Path(__file__).parent / "static"
serializer = URLSafeSerializer(config.ADMIN_SECRET)

app = FastAPI(title="Approval Documents")
app.mount("/pdfjs", StaticFiles(directory=STATIC_DIR / "pdfjs"), name="pdfjs")


def _now():
    return datetime.now(timezone.utc).isoformat()


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
    name: str


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/", response_class=FileResponse)
def dashboard_page():
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/api/documents")
def public_documents():
    return db.list_active_documents()


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
    pages = renderer.render_pdf(data, [title, token, _now()])
    page_count = len(pages)
    original_path = f"{token}/original.pdf"
    storage.upload_original(original_path, data)
    row = db.create_document(token, title, original_path, page_count)
    return {"token": token, "id": row["id"], "url": f"/v/{token}"}


@app.post("/api/request")
def new_request(body: RequestBody, request: Request):
    doc = db.get_document_by_token(body.token)
    if not doc or doc["status"] != "active":
        raise HTTPException(status_code=404, detail="link not found or revoked")
    name = body.name.strip()[:120]
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    client_ip = request.client.host if request.client else None
    req = db.create_access_request(doc["id"], name, ip=client_ip)
    chat_id = config.TELEGRAM_CHAT_ID or db.get_owner_chat_id()
    if chat_id:
        try:
            result = telegram.send_approval_request(chat_id, doc["title"], name, req["id"], ip=client_ip or "")
            if not result.get("ok"):
                print(f"TELEGRAM SEND FAILED: {result.get('description')} chat_id={chat_id}")
        except Exception as exc:
            print(f"TELEGRAM SEND EXCEPTION: {exc} chat_id={chat_id}")
    return {"request_id": req["id"]}


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
        lines = [doc["title"], f"Viewer: {req['visitor_name']}", _now()]
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