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
APP_ICON = "https://approval-docs.onrender.com/static/dashboard.html"


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


def _base_embed(title, color):
    return {
        "title": title,
        "color": color,
        "author": {"name": APP_NAME},
        "footer": {"text": "Documents for Nerds · Approval System"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


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
    title = "New Download Request" if kind == "download" else "New Access Request"
    embed = _base_embed(title, COLOR_BRAND)
    embed["description"] = "Someone is waiting for access. Review the details below."
    embed["fields"] = [
        {"name": "Requester", "value": item["name"], "inline": True},
        {"name": "Document", "value": item["title"], "inline": True},
        {"name": "IP Address", "value": item["ip"] or "Unknown", "inline": True},
    ]
    return embed


def decision_embed(doc, req, action, decided_by, kind="view"):
    is_download = kind == "download"
    if action == "approve":
        title = "Download Approved" if is_download else "Access Approved"
        color = COLOR_GREEN
        mark = "Approve"
    else:
        title = "Download Declined" if is_download else "Access Declined"
        color = COLOR_RED
        mark = "Decline"
    embed = _base_embed(title, color)
    embed["description"] = f"**{mark}** request #{req['id']}"
    embed["fields"] = [
        {"name": "Requester", "value": req["visitor_name"], "inline": True},
        {"name": "Document", "value": doc["title"], "inline": True},
        {"name": "IP Address", "value": req.get("ip") or "Unknown", "inline": True},
        {"name": "Decided by", "value": decided_by, "inline": True},
    ]
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
            mark = "Approved" if r["status"] == "approved" else "Declined"
            color = COLOR_GREEN if r["status"] == "approved" else COLOR_RED
            embed = _base_embed(f"Request #{r['id']} · {mark}", color)
            embed["fields"] = [
                {"name": "Requester", "value": r["visitor_name"], "inline": True},
                {"name": "Document", "value": doc.get("title", "unknown"), "inline": True},
                {"name": "IP Address", "value": r.get("ip") or "Unknown", "inline": True},
                {"name": "Decided by", "value": r.get("decided_by") or "Unknown", "inline": True},
            ]
            embeds.append(embed)
    return embeds, components


def send_request_embeds(items):
    """Send one Discord message per up-to-5 chunk. Returns [(message_id, request_ids)]."""
    webhook_id, webhook_token = _webhook_parts()
    if not webhook_id:
        print("DISCORD WEBHOOK URL NOT SET")
        return []
    results = []
    for i in range(0, len(items), 5):
        chunk = items[i:i + 5]
        embeds = [request_embed(it) for it in chunk]
        components = [_button_row(it) for it in chunk]
        payload = {"embeds": embeds, "components": components}
        resp = requests.post(f"{API}/webhooks/{webhook_id}/{webhook_token}", json=payload, timeout=30)
        if resp.status_code in (200, 204):
            data = resp.json() if resp.status_code == 200 else {}
            results.append((data.get("id"), [it["request_id"] for it in chunk]))
        else:
            print(f"DISCORD SEND FAILED: {resp.status_code} {resp.text[:200]}")
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