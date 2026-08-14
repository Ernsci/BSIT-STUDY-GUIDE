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


def revoke_document(doc_id):
    client().table("documents").update({"status": "revoked"}).eq("id", doc_id).execute()


def create_access_request(document_id, visitor_name):
    row = client().table("access_requests").insert({
        "document_id": document_id,
        "visitor_name": visitor_name,
        "status": "pending",
    }).execute().data[0]
    return row


def get_access_request(request_id):
    data = client().table("access_requests").select("*").eq("id", request_id).execute().data
    return data[0] if data else None


def set_request_status(request_id, status, pages_path=None):
    payload = {"status": status}
    if pages_path is not None:
        payload["pages_path"] = pages_path
    client().table("access_requests").update(payload).eq("id", request_id).execute()


def log_view(request_id, page_number, ip, user_agent):
    client().table("view_logs").insert({
        "request_id": request_id,
        "page_number": page_number,
        "ip": ip,
        "user_agent": user_agent,
    }).execute()