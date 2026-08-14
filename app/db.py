from .supabase_client import client


def get_owner_chat_id():
    data = client().table("settings").select("value").eq("key", "owner_chat_id").execute().data
    return data[0]["value"] if data else None


def set_owner_chat_id(chat_id):
    client().table("settings").upsert({"key": "owner_chat_id", "value": str(chat_id)}).execute()


def create_document(token, title, original_path, page_count):
    row = client().table("documents").insert({
        "token": token,
        "title": title,
        "original_path": original_path,
        "page_count": page_count,
        "status": "active",
    }).execute().data[0]
    return row


def get_document_by_token(token):
    data = client().table("documents").select("*").eq("token", token).execute().data
    return data[0] if data else None


def get_document(doc_id):
    data = client().table("documents").select("*").eq("id", doc_id).execute().data
    return data[0] if data else None


def list_documents():
    return client().table("documents").select("*").order("id", desc=True).execute().data


def list_active_documents():
    return (
        client().table("documents")
        .select("id, token, title, page_count, status")
        .eq("status", "active")
        .order("id", desc=True)
        .execute()
        .data
    )


def revoke_document(doc_id):
    client().table("documents").update({"status": "revoked"}).eq("id", doc_id).execute()


def delete_document(doc_id):
    client().table("documents").delete().eq("id", doc_id).execute()


def create_access_request(document_id, visitor_name, ip=None, kind="view", user_id=None):
    payload = {
        "document_id": document_id,
        "visitor_name": visitor_name,
        "status": "pending",
        "kind": kind,
    }
    if ip is not None:
        payload["ip"] = ip
    if user_id is not None:
        payload["user_id"] = user_id
    row = client().table("access_requests").insert(payload).execute().data[0]
    return row


def get_access_request(request_id):
    data = client().table("access_requests").select("*").eq("id", request_id).execute().data
    return data[0] if data else None


def get_latest_request(document_id, user_id, kind, status):
    data = (
        client().table("access_requests")
        .select("*")
        .eq("document_id", document_id)
        .eq("user_id", user_id)
        .eq("kind", kind)
        .eq("status", status)
        .order("id", desc=True)
        .limit(1)
        .execute()
        .data
    )
    return data[0] if data else None


def set_request_status(request_id, status, pages_path=None, decided_by=None):
    payload = {"status": status}
    if pages_path is not None:
        payload["pages_path"] = pages_path
    if decided_by is not None:
        payload["decided_by"] = decided_by
    client().table("access_requests").update(payload).eq("id", request_id).execute()


def log_view(request_id, page_number, ip, user_agent):
    client().table("view_logs").insert({
        "request_id": request_id,
        "page_number": page_number,
        "ip": ip,
        "user_agent": user_agent,
    }).execute()


def create_user(name, email, password_hash):
    row = client().table("users").insert({
        "name": name,
        "email": email.lower(),
        "password_hash": password_hash,
    }).execute().data[0]
    return row


def get_user_by_email(email):
    data = client().table("users").select("*").eq("email", email.lower()).execute().data
    return data[0] if data else None


def get_user(user_id):
    data = client().table("users").select("*").eq("id", user_id).execute().data
    return data[0] if data else None


def count_pending_requests(user_id):
    data = (
        client().table("access_requests")
        .select("id")
        .eq("user_id", user_id)
        .eq("status", "pending")
        .execute()
        .data
    )
    return len(data)


def last_request_at(user_id):
    data = (
        client().table("access_requests")
        .select("requested_at")
        .eq("user_id", user_id)
        .order("requested_at", desc=True)
        .limit(1)
        .execute()
        .data
    )
    return data[0]["requested_at"] if data else None