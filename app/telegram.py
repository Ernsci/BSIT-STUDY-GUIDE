import requests

from . import config

API = "https://api.telegram.org"


def _call(method, **params):
    url = f"{API}/bot{config.TELEGRAM_BOT_TOKEN}/{method}"
    resp = requests.post(url, json=params, timeout=30)
    return resp.json()


def send_approval_request(chat_id, title, visitor_name, request_id, ip=""):
    return _call(
        "sendMessage",
        chat_id=chat_id,
        text=format_request(title, visitor_name, ip),
        reply_markup={
            "inline_keyboard": [[
                {"text": "✅ Approve", "callback_data": f"approve:{request_id}"},
                {"text": "❌ Decline", "callback_data": f"decline:{request_id}"},
            ]]
        },
    )


def send_download_request(chat_id, title, visitor_name, request_id, ip=""):
    return _call(
        "sendMessage",
        chat_id=chat_id,
        text=format_request(title, visitor_name, ip, kind="download"),
        reply_markup={
            "inline_keyboard": [[
                {"text": "⬇️ Approve download", "callback_data": f"dapprove:{request_id}"},
                {"text": "❌ Decline", "callback_data": f"ddecline:{request_id}"},
            ]]
        },
    )


def send_batch_requests(chat_id, items):
    """Send one message grouping several pending requests, one button-row each."""
    lines = [f"📥 {len(items)} new request{'s' if len(items) != 1 else ''}:"]
    keyboard = []
    for idx, it in enumerate(items, 1):
        is_download = it.get("kind") == "download"
        label = "Download Request" if is_download else "Access Request"
        lines.append(
            f"\n{idx}. {label}\n"
            f"👤 Name: {it['name']}\n"
            f"📄 File: {it['title']}\n"
            f"🌐 IP: {it['ip'] or 'Unknown'}"
        )
        req_id = it["request_id"]
        if is_download:
            keyboard.append([
                {"text": f"⬇️ Approve {idx}", "callback_data": f"dapprove:{req_id}"},
                {"text": f"❌ Decline {idx}", "callback_data": f"ddecline:{req_id}"},
            ])
        else:
            keyboard.append([
                {"text": f"✅ Approve {idx}", "callback_data": f"approve:{req_id}"},
                {"text": f"❌ Decline {idx}", "callback_data": f"decline:{req_id}"},
            ])
    return _call(
        "sendMessage",
        chat_id=chat_id,
        text="\n".join(lines),
        reply_markup={"inline_keyboard": keyboard},
    )


def format_request(title, name, ip="", kind="view"):
    ip = ip or "Unknown"
    label = "Download Request" if kind == "download" else "Access Request"
    return (
        f"📥 New {label}\n"
        f"─────────────\n"
        f"👤 Name: {name}\n"
        f"📄 File: {title}\n"
        f"🌐 IP: {ip}"
    )


def format_decision(title, name, ip, action, by, kind="view"):
    ip = ip or "Unknown"
    is_download = kind == "download"
    if action == "approve":
        head = "⬇️ Download Approved" if is_download else "✅ Access Approved"
    else:
        head = "❌ Download Declined" if is_download else "❌ Access Declined"
    return (
        f"{head}\n"
        f"─────────────\n"
        f"👤 Name: {name}\n"
        f"📄 File: {title}\n"
        f"🌐 IP: {ip}\n"
        f"🖊️ By: {by}"
    )


def send_text(chat_id, text):
    return _call("sendMessage", chat_id=chat_id, text=text)


def edit_message(chat_id, message_id, text, reply_markup=None):
    params = {"chat_id": chat_id, "message_id": message_id, "text": text}
    if reply_markup is not None:
        params["reply_markup"] = reply_markup
    return _call("editMessageText", **params)


def answer_callback(callback_id, text):
    return _call("answerCallbackQuery", callback_id=callback_id, text=text)


def set_webhook(url):
    params = {"url": url}
    if config.TELEGRAM_WEBHOOK_SECRET:
        params["secret_token"] = config.TELEGRAM_WEBHOOK_SECRET
    return _call("setWebhook", **params)


def get_updates(offset=0, timeout=25):
    resp = requests.post(
        f"{API}/bot{config.TELEGRAM_BOT_TOKEN}/getUpdates",
        json={"offset": offset, "timeout": timeout},
        timeout=timeout + 10,
    )
    return resp.json().get("result", [])