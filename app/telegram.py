import requests

from . import config

API = "https://api.telegram.org"


def _call(method, **params):
    url = f"{API}/bot{config.TELEGRAM_BOT_TOKEN}/{method}"
    resp = requests.post(url, json=params, timeout=30)
    return resp.json()


def send_approval_request(chat_id, title, visitor_name, request_id):
    return _call(
        "sendMessage",
        chat_id=chat_id,
        text=f"Access request for '{title}'\nFrom: {visitor_name}",
        reply_markup={
            "inline_keyboard": [[
                {"text": "Approve", "callback_data": f"approve:{request_id}"},
                {"text": "Decline", "callback_data": f"decline:{request_id}"},
            ]]
        },
    )


def send_text(chat_id, text):
    return _call("sendMessage", chat_id=chat_id, text=text)


def edit_message(chat_id, message_id, text):
    return _call("editMessageText", chat_id=chat_id, message_id=message_id, text=text)


def answer_callback(callback_id, text):
    return _call("answerCallbackQuery", callback_id=callback_id, text=text)


def set_webhook(url):
    return _call("setWebhook", url=url)


def get_updates(offset=0, timeout=25):
    resp = requests.post(
        f"{API}/bot{config.TELEGRAM_BOT_TOKEN}/getUpdates",
        json={"offset": offset, "timeout": timeout},
        timeout=timeout + 10,
    )
    return resp.json().get("result", [])