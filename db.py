"""SQLite storage for forms, access control and the notification outbox."""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import config

SCHEMA_VERSION = 2
RATE_WINDOW = 15 * 60
CLIENT_SUBMISSION_LIMIT = 5
GLOBAL_SUBMISSION_LIMIT = 120
INTEGRATION_SUBMISSION_LIMIT = 30
SUBMISSION_KEY_RETENTION = 24 * 60 * 60
TRASH_RETENTION_DAYS = 30
AUDIT_RETENTION_DAYS = 90
NOTIFICATION_LEASE_SECONDS = 60
MAX_NOTIFICATION_ATTEMPTS = 5
MAX_ACTIVE_API_KEYS = 20
MAX_LISTED_API_KEYS = 100
MAX_API_KEYS_CREATED_DAILY = 100

MAX_TELEGRAM_ID = (1 << 52) - 1
VALID_USER_ID = (
    "user_id GLOB '[1-9]*' AND user_id NOT GLOB '*[^0-9]*' "
    f"AND CAST(user_id AS INTEGER) <= {MAX_TELEGRAM_ID}"
)
FORM_FILTERS = {
    "all": "deleted_at IS NULL",
    "new": "deleted_at IS NULL AND viewed = 0",
    "viewed": "deleted_at IS NULL AND viewed = 1",
    "deleted": "deleted_at IS NOT NULL",
}
API_KEY_FIELDS = "id, label, origin, created_at, expires_at, revoked_at"


class PermissionDenied(Exception):
    pass


class SubmissionRateLimited(Exception):
    def __init__(self, retry_after):
        super().__init__("Submission rate limit exceeded")
        self.retry_after = retry_after


class FormTokenConflict(Exception):
    pass


class ApiKeyLimit(Exception):
    pass


class IntegrationUnavailable(Exception):
    pass


@contextmanager
def get_db(*, write=False, snapshot=False):
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA secure_delete = ON")
        if write:
            conn.execute("BEGIN IMMEDIATE")
        elif snapshot:
            conn.execute("BEGIN")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _prepare_database_file():
    path = Path(config.DATABASE_PATH)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "rb+") as database:
        if not stat.S_ISREG(os.fstat(database.fileno()).st_mode):
            raise RuntimeError("DATABASE_PATH must refer to a regular file")
        if os.name == "posix":
            os.fchmod(database.fileno(), 0o600)


def init_db():
    _prepare_database_file()
    with get_db(write=True) as conn:
        current_version = conn.execute("PRAGMA user_version").fetchone()[0]
        if not 0 <= current_version <= SCHEMA_VERSION:
            raise RuntimeError("Unsupported SQLite schema version")
        if current_version == 0:
            _migrate_original_schema(conn)
        if current_version < 2:
            _migrate_integrations(conn)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _migrate_original_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            form_id TEXT,
            viewed INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT
        )
    """)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(forms)")}
    additions = {
        "phone": "TEXT NOT NULL DEFAULT ''",
        "email": "TEXT NOT NULL DEFAULT ''",
        "form_id": "TEXT",
        "viewed": "INTEGER NOT NULL DEFAULT 0",
        "deleted_at": "TEXT",
    }
    for column, definition in additions.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE forms ADD COLUMN {column} {definition}")
    conn.execute("UPDATE forms SET viewed = 0 WHERE viewed IS NULL OR viewed NOT IN (0, 1)")
    if "email_or_phone" in columns:
        conn.execute("""
            UPDATE forms SET email = trim(email_or_phone)
            WHERE COALESCE(email, '') = '' AND instr(email_or_phone, '@') > 0
        """)
        conn.execute("""
            UPDATE forms SET phone = trim(email_or_phone)
            WHERE COALESCE(phone, '') = '' AND instr(email_or_phone, '@') = 0
              AND trim(email_or_phone) != ''
        """)
    conn.execute("CREATE INDEX IF NOT EXISTS forms_by_deleted ON forms (deleted_at, id)")
    conn.execute("CREATE INDEX IF NOT EXISTS forms_by_viewed ON forms (viewed, id) WHERE deleted_at IS NULL")
    conn.execute("""
        CREATE TABLE submission_keys (
            token TEXT PRIMARY KEY,
            payload_digest TEXT NOT NULL,
            form_id INTEGER REFERENCES forms(id) ON DELETE SET NULL,
            created_at INTEGER NOT NULL
        )
    """)
    conn.execute("CREATE INDEX submission_keys_by_created ON submission_keys (created_at)")
    conn.execute("""
        CREATE TABLE submission_events (
            address_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    conn.execute("CREATE INDEX submission_events_by_created ON submission_events (created_at)")
    conn.execute("""
        CREATE TABLE notifications (
            id INTEGER PRIMARY KEY,
            form_id INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
            chat_id TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            available_at INTEGER NOT NULL,
            lease_token TEXT,
            finished_at INTEGER,
            outcome TEXT,
            UNIQUE (form_id, chat_id)
        )
    """)
    conn.execute("CREATE INDEX pending_notifications ON notifications (available_at, id) WHERE finished_at IS NULL")
    conn.execute("""
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY,
            occurred_at INTEGER NOT NULL,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX audit_events_by_time ON audit_events (occurred_at)")


def _migrate_integrations(conn):
    conn.execute("""
        CREATE TABLE api_keys (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            origin TEXT NOT NULL,
            secret_digest BLOB NOT NULL CHECK (length(secret_digest) = 32),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
            revoked_at INTEGER
        )
    """)
    conn.execute("CREATE INDEX api_keys_by_expiry ON api_keys (expires_at) WHERE revoked_at IS NULL")
    conn.execute("CREATE INDEX api_keys_by_creation ON api_keys (created_at)")
    conn.execute("ALTER TABLE submission_events ADD COLUMN integration_id TEXT")
    conn.execute("""
        CREATE INDEX submission_events_by_integration
        ON submission_events (integration_id, created_at) WHERE integration_id IS NOT NULL
    """)


def _telegram_id(user_id):
    value = str(user_id)
    if not value.isascii() or not value.isdecimal() or value.startswith("0"):
        return None
    if len(value) > 16 or int(value) > MAX_TELEGRAM_ID:
        return None
    return value


def _role(conn, user_id):
    value = _telegram_id(user_id)
    if value is None:
        return None
    row = conn.execute("SELECT is_admin FROM users WHERE user_id = ?", (value,)).fetchone()
    if row is None:
        return None
    return "admin" if row["is_admin"] == 1 else "moderator"


def _authorize(conn, actor_id, *, admin=False):
    role = _role(conn, actor_id)
    if role is None or (admin and role != "admin"):
        raise PermissionDenied


def _audit(conn, actor_id, action, target):
    conn.execute(
        "INSERT INTO audit_events (occurred_at, actor_id, action, target) VALUES (?, ?, ?, ?)",
        (int(time.time()), str(actor_id), action, str(target)),
    )


def get_user_role(user_id):
    with get_db() as conn:
        return _role(conn, user_id)


def is_authorized(user_id):
    return get_user_role(user_id) is not None


def is_admin(user_id):
    return get_user_role(user_id) == "admin"


def bootstrap_admin(user_id):
    value = _telegram_id(user_id)
    if value is None:
        raise ValueError("Invalid Telegram user ID")
    with get_db(write=True) as conn:
        if _admin_count(conn):
            return False
        conn.execute(
            "INSERT INTO users (user_id, is_admin) VALUES (?, 1) "
            "ON CONFLICT(user_id) DO UPDATE SET is_admin = 1",
            (value,),
        )
        _audit(conn, "local", "bootstrap_admin", value)
    return True


def _admin_count(conn):
    return conn.execute(f"SELECT count(*) FROM users WHERE is_admin = 1 AND {VALID_USER_ID}").fetchone()[0]


def add_user(user_id, is_admin_flag=0, actor_id=None):
    value = _telegram_id(user_id)
    if value is None:
        raise ValueError("Invalid Telegram user ID")
    with get_db(write=True) as conn:
        _authorize(conn, actor_id, admin=True)
        inserted = conn.execute(
            "INSERT INTO users (user_id, is_admin) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING",
            (value, int(bool(is_admin_flag))),
        ).rowcount
        if inserted:
            action = "grant_admin" if is_admin_flag else "grant_moderator"
            _audit(conn, actor_id, action, value)
        return bool(inserted)


def remove_user(user_id, actor_id=None, *, moderators_only=False):
    value = _telegram_id(user_id)
    if value is None:
        raise ValueError("Invalid Telegram user ID")
    with get_db(write=True) as conn:
        _authorize(conn, actor_id, admin=True)
        if _role(conn, value) == "admin" and (moderators_only or _admin_count(conn) <= 1):
            return False
        deleted = conn.execute("DELETE FROM users WHERE user_id = ?", (value,)).rowcount
        if deleted:
            _audit(conn, actor_id, "revoke_access", value)
        return bool(deleted)


def add_moderator(user_id, actor_id):
    return add_user(user_id, actor_id=actor_id)


def remove_moderator(user_id, actor_id):
    return remove_user(user_id, actor_id=actor_id, moderators_only=True)


def get_moderators(limit=None, offset=0, *, actor_id):
    with get_db(snapshot=True) as conn:
        _authorize(conn, actor_id, admin=True)
        rows = conn.execute(
            f"SELECT user_id FROM users WHERE COALESCE(is_admin, 0) != 1 AND {VALID_USER_ID} "
            "ORDER BY id ASC LIMIT ? OFFSET ?",
            (-1 if limit is None else limit, offset),
        )
        return [dict(row) for row in rows]


def list_api_keys(actor_id):
    with get_db(snapshot=True) as conn:
        _authorize(conn, actor_id, admin=True)
        now = int(time.time())
        rows = conn.execute(
            f"SELECT {API_KEY_FIELDS} FROM api_keys "
            "ORDER BY (revoked_at IS NULL AND expires_at > ?) DESC, created_at DESC, rowid DESC LIMIT ?",
            (now, MAX_LISTED_API_KEYS),
        )
        return [dict(row) for row in rows]


def create_api_key(label, origin, expires_days, actor_id):
    with get_db(write=True) as conn:
        _authorize(conn, actor_id, admin=True)
        now = int(time.time())
        active_count = conn.execute(
            "SELECT count(*) FROM api_keys WHERE revoked_at IS NULL AND expires_at > ?",
            (now,),
        ).fetchone()[0]
        recent_count = conn.execute(
            "SELECT count(*) FROM api_keys WHERE created_at > ?",
            (now - 86400,),
        ).fetchone()[0]
        if active_count >= MAX_ACTIVE_API_KEYS or recent_count >= MAX_API_KEYS_CREATED_DAILY:
            raise ApiKeyLimit
        key_id = secrets.token_urlsafe(18)
        secret = secrets.token_urlsafe(32)
        record = conn.execute(
            "INSERT INTO api_keys (id, label, origin, secret_digest, created_at, expires_at) "
            f"VALUES (?, ?, ?, ?, ?, ?) RETURNING {API_KEY_FIELDS}",
            (key_id, label, origin, _digest_secret(secret), now, now + expires_days * 86400),
        ).fetchone()
        _audit(conn, actor_id, "create_api_key", key_id)
        return dict(record), f"fsk_{key_id}.{secret}"


def revoke_api_key(key_id, actor_id):
    with get_db(write=True) as conn:
        _authorize(conn, actor_id, admin=True)
        changed = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (int(time.time()), key_id),
        ).rowcount
        if changed:
            _audit(conn, actor_id, "revoke_api_key", key_id)
            return True
        return conn.execute("SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone() is not None


def _digest_secret(secret):
    return hashlib.sha256(secret.encode("ascii")).digest()


def _active_api_key(conn, key_id, now, *, fields=API_KEY_FIELDS):
    return conn.execute(
        f"SELECT {fields} FROM api_keys WHERE id = ? AND revoked_at IS NULL AND expires_at > ?",
        (key_id, now),
    ).fetchone()


def get_active_api_key(key_id):
    with get_db() as conn:
        row = _active_api_key(conn, key_id, int(time.time()))
        return dict(row) if row else None


def _valid_api_secret(row, secret):
    return row is not None and hmac.compare_digest(row["secret_digest"], _digest_secret(secret))


def is_api_key_authorized(key_id, secret):
    with get_db() as conn:
        row = _active_api_key(conn, key_id, int(time.time()), fields="secret_digest")
        return _valid_api_secret(row, secret)


def _utc_now():
    return datetime.now(timezone.utc)


def _format_time(timestamp):
    return timestamp.isoformat(timespec="seconds")


def submit_form(name, phone, email, message, form_id, client_address, *, integration_id=None, key_secret=None):
    digest = hashlib.sha256(json.dumps([name, phone, email, message], ensure_ascii=False).encode()).hexdigest()
    idempotency_key = form_id
    if integration_id is not None:
        channel = "embed" if key_secret is None else "api"
        idempotency_key = f"{channel}:{integration_id}:{form_id}"
    with get_db(write=True) as conn:
        now = _utc_now()
        epoch = int(now.timestamp())
        if integration_id is not None:
            integration = _active_api_key(conn, integration_id, epoch, fields="secret_digest")
            if integration is None or (key_secret is not None and not _valid_api_secret(integration, key_secret)):
                raise IntegrationUnavailable
        elif key_secret is not None:
            raise IntegrationUnavailable

        key = conn.execute(
            "SELECT payload_digest, form_id FROM submission_keys WHERE token = ?", (idempotency_key,)
        ).fetchone()
        if key is not None:
            if key["payload_digest"] != digest:
                raise FormTokenConflict
            return key["form_id"], False

        _consume_submission_quota(conn, client_address, epoch, integration_id, from_api=key_secret is not None)
        row = conn.execute(
            "INSERT INTO forms (name, phone, email, message, timestamp, form_id, viewed) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (name, phone, email, message, _format_time(now), form_id),
        )
        record_id = row.lastrowid
        conn.execute(
            "INSERT INTO submission_keys (token, payload_digest, form_id, created_at) VALUES (?, ?, ?, ?)",
            (idempotency_key, digest, record_id, epoch),
        )
        conn.execute(
            "INSERT INTO notifications (form_id, chat_id, available_at) "
            f"SELECT ?, user_id, ? FROM users WHERE is_admin = 1 AND {VALID_USER_ID}",
            (record_id, epoch),
        )
        return record_id, True


def _quota_delay(conn, limit, now, *, where="", args=()):
    count, oldest = conn.execute(f"SELECT count(*), min(created_at) FROM submission_events {where}", args).fetchone()
    return oldest + RATE_WINDOW - now if count >= limit else 0


def _consume_submission_quota(conn, client_address, now, integration_id, *, from_api):
    conn.execute("DELETE FROM submission_events WHERE created_at <= ?", (now - RATE_WINDOW,))
    retry_after = _quota_delay(conn, GLOBAL_SUBMISSION_LIMIT, now)
    if integration_id is not None:
        retry_after = max(retry_after, _quota_delay(
            conn, INTEGRATION_SUBMISSION_LIMIT, now, where="WHERE integration_id = ?", args=(integration_id,),
        ))
    if not from_api:
        retry_after = max(retry_after, _quota_delay(
            conn, CLIENT_SUBMISSION_LIMIT, now, where="WHERE address_key = ?", args=(client_address,),
        ))
    if retry_after:
        raise SubmissionRateLimited(retry_after)
    conn.execute(
        "INSERT INTO submission_events (address_key, created_at, integration_id) VALUES (?, ?, ?)",
        ("server-api" if from_api else client_address, now, integration_id),
    )


def _stats(conn, *, include_deleted):
    row = conn.execute("""
        SELECT
            count(CASE WHEN deleted_at IS NULL THEN 1 END) AS total,
            count(CASE WHEN deleted_at IS NULL AND viewed = 0 THEN 1 END) AS unviewed,
            count(CASE WHEN deleted_at IS NULL AND viewed = 1 THEN 1 END) AS viewed,
            count(CASE WHEN deleted_at IS NOT NULL THEN 1 END) AS deleted
        FROM forms
    """).fetchone()
    result = dict(row)
    if not include_deleted:
        del result["deleted"]
    return result


def get_stats(include_deleted=False):
    with get_db() as conn:
        return _stats(conn, include_deleted=include_deleted)


def get_form_page(status, before, limit, include_deleted=False):
    conditions = FORM_FILTERS[status]
    args = [limit + 1]
    if before is not None:
        conditions += " AND id < ?"
        args.insert(0, before)
    with get_db(snapshot=True) as conn:
        items = [
            dict(row) for row in conn.execute(
                f"SELECT id, name, timestamp, viewed, deleted_at FROM forms WHERE {conditions} "
                "ORDER BY id DESC LIMIT ?", args
            )
        ]
        next_cursor = items[limit - 1]["id"] if len(items) > limit else None
        return {
            "items": items[:limit],
            "next_cursor": next_cursor,
            "counts": _stats(conn, include_deleted=include_deleted),
        }


def get_form(form_id, include_deleted=False):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, phone, email, message, timestamp, viewed, deleted_at "
            "FROM forms WHERE id = ? AND (? OR deleted_at IS NULL)",
            (form_id, int(include_deleted)),
        ).fetchone()
        return dict(row) if row else None


def set_viewed(form_id, viewed, actor_id):
    with get_db(write=True) as conn:
        _authorize(conn, actor_id)
        row = conn.execute("SELECT viewed FROM forms WHERE id = ? AND deleted_at IS NULL", (form_id,)).fetchone()
        if row is None:
            return False
        if row["viewed"] != viewed:
            conn.execute("UPDATE forms SET viewed = ? WHERE id = ?", (int(viewed), form_id))
            _audit(conn, actor_id, "mark_viewed" if viewed else "mark_unviewed", form_id)
        return True


def delete_form(form_id, actor_id):
    with get_db(write=True) as conn:
        _authorize(conn, actor_id, admin=True)
        now = _utc_now()
        changed = conn.execute(
            "UPDATE forms SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
            (_format_time(now), form_id),
        ).rowcount
        if changed:
            _audit(conn, actor_id, "trash_form", form_id)
            conn.execute(
                "UPDATE notifications SET finished_at = ?, outcome = 'cancelled', lease_token = NULL "
                "WHERE form_id = ? AND finished_at IS NULL",
                (int(now.timestamp()), form_id),
            )
            return True
        return conn.execute("SELECT 1 FROM forms WHERE id = ?", (form_id,)).fetchone() is not None


def restore_form(form_id, actor_id):
    with get_db(write=True) as conn:
        _authorize(conn, actor_id, admin=True)
        changed = conn.execute(
            "UPDATE forms SET deleted_at = NULL WHERE id = ? AND deleted_at IS NOT NULL",
            (form_id,),
        ).rowcount
        if changed:
            _audit(conn, actor_id, "restore_form", form_id)
            return True
        return conn.execute("SELECT 1 FROM forms WHERE id = ?", (form_id,)).fetchone() is not None


def claim_notification():
    with get_db(write=True) as conn:
        now = int(time.time())
        conn.execute(
            "UPDATE notifications SET finished_at = ?, outcome = 'failed', lease_token = NULL "
            "WHERE attempts >= ? AND finished_at IS NULL AND available_at <= ?",
            (now, MAX_NOTIFICATION_ATTEMPTS, now),
        )
        task = conn.execute(
            "SELECT id, form_id, chat_id, attempts FROM notifications "
            "WHERE finished_at IS NULL AND available_at <= ? ORDER BY available_at, id LIMIT 1",
            (now,),
        ).fetchone()
        if task is None:
            return None
        lease_token = secrets.token_urlsafe(24)
        conn.execute(
            "UPDATE notifications SET attempts = attempts + 1, available_at = ?, lease_token = ? WHERE id = ?",
            (now + NOTIFICATION_LEASE_SECONDS, lease_token, task["id"]),
        )
        return {**dict(task), "attempts": task["attempts"] + 1, "lease_token": lease_token}


def finish_notification(notification_id, lease_token, outcome, delay_seconds=0):
    now = int(time.time())
    with get_db(write=True) as conn:
        if outcome == "retry":
            changed = conn.execute(
                "UPDATE notifications SET available_at = ?, lease_token = NULL "
                "WHERE id = ? AND lease_token = ? AND finished_at IS NULL",
                (now + min(86400, max(1, int(delay_seconds))), notification_id, lease_token),
            ).rowcount
        else:
            changed = conn.execute(
                "UPDATE notifications SET finished_at = ?, outcome = ?, lease_token = NULL "
                "WHERE id = ? AND lease_token = ? AND finished_at IS NULL",
                (now, outcome, notification_id, lease_token),
            ).rowcount
        return bool(changed)


def prune_expired():
    now = _utc_now()
    epoch = int(now.timestamp())
    with get_db(write=True) as conn:
        cutoff = now - timedelta(days=TRASH_RETENTION_DAYS)
        deleted = conn.execute("DELETE FROM forms WHERE deleted_at <= ?", (_format_time(cutoff),)).rowcount
        if config.ACTIVE_FORMS_RETENTION_DAYS:
            active_cutoff = _format_time(now - timedelta(days=config.ACTIVE_FORMS_RETENTION_DAYS))
            deleted += conn.execute(
                "DELETE FROM forms WHERE deleted_at IS NULL AND julianday(timestamp) <= julianday(?)",
                (active_cutoff,),
            ).rowcount
        conn.execute("DELETE FROM notifications WHERE finished_at <= ?", (int(cutoff.timestamp()),))
        conn.execute("DELETE FROM submission_keys WHERE created_at <= ?", (epoch - SUBMISSION_KEY_RETENTION,))
        conn.execute("DELETE FROM submission_events WHERE created_at <= ?", (epoch - RATE_WINDOW,))
        conn.execute("DELETE FROM api_keys WHERE COALESCE(revoked_at, expires_at) <= ?", (int(cutoff.timestamp()),))
        conn.execute(
            "DELETE FROM audit_events WHERE occurred_at <= ?",
            (int((now - timedelta(days=AUDIT_RETENTION_DAYS)).timestamp()),),
        )
        return deleted
