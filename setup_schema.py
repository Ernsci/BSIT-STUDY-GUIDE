import os

import pg8000
from dotenv import load_dotenv

load_dotenv()

SQL = """
CREATE TABLE IF NOT EXISTS documents (
    id BIGSERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    original_path TEXT NOT NULL,
    page_count INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_requests (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    visitor_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    pages_path TEXT,
    ip TEXT,
    kind TEXT NOT NULL DEFAULT 'view',
    decided_by TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS view_logs (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    page_number INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT,
    viewed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS ip TEXT;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS decided_by TEXT;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'view';
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
"""


def main():
    conn = pg8000.connect(dsn=os.environ["SUPABASE_DB_URL"])
    try:
        conn.run(SQL)
        conn.commit()
        print("Schema created.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()