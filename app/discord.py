import re
from datetime import datetime, timezone

import nacl.exceptions
import nacl.signing
import requests

from . import config, db

API = "https://discord.com/api/v10"

COLOR_BRAND = 0x5865F2
COLOR_GREEN = 0x57F287
COLOR_RED = 0xED4245

APP_NAME = "Documents for Nerds"


def is_configured():
    if config.DISCORD_BOT_TOKEN and config.DISCORD_CHANNEL_ID:
        return True
    webhook_id, _ = _webhook_parts()
    return bool(webhook_id)


def verify_signature(raw_body, signature, timestamp):
    """Verify the Ed25519 signature Discord attaches to interaction POSTs."""
    if not config.DISCORD_PUBLIC_KEY or not signature or not timestamp:
        return False
    try:
        key = nacl.signing.VerifyKey(bytes.fromhex(config.DISCORD_PUBLIC_KEY))
        key.verify(f"{timestamp}".encode() + raw_body, bytes.fromhex(signature))
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False


def _webhook_parts():
    m = re.search(r"/webhooks/([^/]+)/([^/]+)", config.DISCORD_WEBHOOK_URL or "")
    if not m:
        return None, None
    return m.group(1), m.group(2)


def _base_embed(title, color, emoji=""):
    return {
        "title": f"{emoji} {title}".strip(),
        "color": color,
        "author": {"name": APP_NAME},
        "footer": {"text": "Documents for Nerds · Approval System"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _ip_value(ip):
    return f"`{ip}`" if ip else "Unknown"


def _button_row(item):
    req_id = item["request_id"]
    if item["kind"] == "download":
        return {"type": 1, "components": [
            {"type": 2, "style": 3, "label": "Approve download", "custom_id": f"dapprove:{req_id}"},
            {"type": 2, "style": 4, "label": "Decline", "custom_id": f"ddecline:{req_id}"},
        ]}
    return {"type": 1, "components": [
        {"type": 2, "style": 3, "label": "Approve", "custom_id": f"approve:{req_id}"},
        {"type": 2, "style": 4, "label": "Decline", "custom_id": f"decline:{req_id}"},
    ]}


def request_embed(item):
    kind = item.get("kind") or "view"
    is_download = kind == "download"
    emoji = "📥" if is_download else "🔔"
    title = "New Download Request" if is_download else "New Access Request"
    embed = _base_embed(title, COLOR_BRAND, emoji)
    name = item["name"]
    doc_title = item["title"]
    embed["description"] = (
        f"**{name}** is waiting for access to **{doc_title}**. "
        f"Tap a button below to approve or decline."
    )
    embed["fields"] = [
        {"name": "👤 Requester", "value": name, "inline": True},
        {"name": "📄 Document", "value": doc_title, "inline": True},
        {"name": "🖥️ IP Address", "value": _ip_value(item.get("ip")), "inline": True},
        {"name": "🧾 Request #", "value": f"`{item['request_id']}`", "inline": True},
    ]
    return embed


def decision_embed(doc, req, action, decided_by, kind="view"):
    is_download = kind == "download"
    approved = action == "approve"
    emoji = "✅" if approved else "❌"
    if approved:
        title = "Download Approved" if is_download else "Access Approved"
        color = COLOR_GREEN
    else:
        title = "Download Declined" if is_download else "Access Declined"
        color = COLOR_RED
    embed = _base_embed(title, color, emoji)
    embed["description"] = (
        f"**{req['visitor_name']}**'s request for **{doc['title']}** has been "
        f"{'approved' if approved else 'declined'}."
    )
    embed["fields"] = [
        {"name": "👤 Requester", "value": req["visitor_name"], "inline": True},
        {"name": "📄 Document", "value": doc["title"], "inline": True},
        {"name": "🖥️ IP Address", "value": _ip_value(req.get("ip")), "inline": True},
        {"name": "🔎 Decided by", "value": decided_by, "inline": True},
    ]
    embed["footer"] = {"text": f"Request #{req['id']} · Documents for Nerds"}
    return embed


def build_batch_embeds_and_components(reqs):
    """Build embeds + components from current DB state for a grouped message.
    Decided requests become plain embeds; pending ones keep their buttons."""
    docs = {}
    for r in reqs:
        if r["document_id"] not in docs:
            docs[r["document_id"]] = db.get_document(r["document_id"]) or {"title": "unknown"}
    embeds = []
    components = []
    for r in reqs:
        doc = docs[r["document_id"]]
        if r["status"] == "pending":
            embeds.append(request_embed({
                "name": r["visitor_name"],
                "title": doc.get("title", "unknown"),
                "ip": r.get("ip") or "",
                "kind": r.get("kind") or "view",
                "request_id": r["id"],
            }))
            components.append(_button_row({
                "kind": r.get("kind") or "view",
                "request_id": r["id"],
            }))
        else:
            approved = r["status"] == "approved"
            mark = "Approved" if approved else "Declined"
            color = COLOR_GREEN if approved else COLOR_RED
            embed = _base_embed(f"Request #{r['id']} · {mark}", color, "✅" if approved else "❌")
            embed["description"] = f"**{r['visitor_name']}**'s request for **{doc.get('title', 'unknown')}** was {mark.lower()}."
            embed["fields"] = [
                {"name": "👤 Requester", "value": r["visitor_name"], "inline": True},
                {"name": "📄 Document", "value": doc.get("title", "unknown"), "inline": True},
                {"name": "🖥️ IP Address", "value": _ip_value(r.get("ip")), "inline": True},
                {"name": "🔎 Decided by", "value": r.get("decided_by") or "Unknown", "inline": True},
            ]
            embeds.append(embed)
    return embeds, components


def _send_payload(payload):
    """Send a message via the bot (clickable buttons) or fall back to the webhook."""
    if config.DISCORD_BOT_TOKEN and config.DISCORD_CHANNEL_ID:
        headers = {"Authorization": f"Bot {config.DISCORD_BOT_TOKEN}"}
        url = f"{API}/channels/{config.DISCORD_CHANNEL_ID}/messages"
    else:
        webhook_id, webhook_token = _webhook_parts()
        if not webhook_id:
            print("DISCORD WEBHOOK URL NOT SET")
            return None
        headers = {}
        url = f"{API}/webhooks/{webhook_id}/{webhook_token}"
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    if resp.status_code in (200, 204):
        return resp.json() if resp.status_code == 200 else {}
    print(f"DISCORD SEND FAILED: {resp.status_code} {resp.text[:200]}")
    return None


def send_request_embeds(items):
    """Send one Discord message per up-to-5 chunk. Returns [(message_id, request_ids)]."""
    results = []
    for i in range(0, len(items), 5):
        chunk = items[i:i + 5]
        embeds = [request_embed(it) for it in chunk]
        components = [_button_row(it) for it in chunk]
        payload = {"embeds": embeds, "components": components}
        data = _send_payload(payload)
        if data is not None:
            results.append((data.get("id"), [it["request_id"] for it in chunk]))
    return results


def edit_message(edit_spec, embeds, components):
    """Edit the original message after a button interaction."""
    app_id = edit_spec.get("app_id")
    interaction_token = edit_spec.get("interaction_token")
    if not app_id or not interaction_token:
        print("DISCORD: no interaction token to edit message")
        return
    payload = {"embeds": embeds, "components": components}
    url = f"{API}/webhooks/{app_id}/{interaction_token}/messages/@original"
    resp = requests.patch(url, json=payload, timeout=30)
    if resp.status_code not in (200, 204):
        print(f"DISCORD EDIT FAILED: {resp.status_code} {resp.text[:200]}")