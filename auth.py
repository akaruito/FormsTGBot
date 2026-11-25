import hashlib
import hmac
import json
import re
import time
from functools import wraps
from urllib.parse import parse_qsl

from flask import g, jsonify, request

import config
import db


INIT_DATA_MAX_AGE = 15 * 60
CLOCK_SKEW = 30
MAX_TELEGRAM_USER_ID = (1 << 52) - 1
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
HASH = re.compile(r"[a-f0-9]{64}")
TIMESTAMP = re.compile(r"[0-9]{1,12}")
INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")


def _unique_object(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("Duplicate JSON field")
    return fields


def validate_telegram_init_data(init_data_raw: str, bot_token: str) -> dict | None:
    """Verify first-party Telegram Mini App credentials and extract a fresh user ID."""
    if not init_data_raw or not bot_token or len(init_data_raw) > 8192:
        return None
    if any(not 0x21 <= ord(character) <= 0x7E for character in init_data_raw):
        return None
    if INVALID_PERCENT.search(init_data_raw):
        return None

    try:
        pairs = parse_qsl(
            init_data_raw,
            keep_blank_values=True,
            strict_parsing=True,
            errors="strict",
            max_num_fields=32,
        )
    except ValueError:
        return None

    fields = dict(pairs)
    if len(fields) != len(pairs) or any(
        not FIELD_NAME.fullmatch(key) or any(separator in value for separator in ("\r", "\n", "\0"))
        for key, value in pairs
    ):
        return None

    received_hash = fields.pop("hash", "")
    auth_date = fields.get("auth_date", "")
    if not HASH.fullmatch(received_hash) or not TIMESTAMP.fullmatch(auth_date):
        return None

    # The first-party HMAC includes every field except hash, including signature if present.
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret = hmac.digest(b"WebAppData", bot_token.encode(), hashlib.sha256)
    expected_hash = hmac.new(secret, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hash, received_hash):
        return None

    age = int(time.time()) - int(auth_date)
    if not -CLOCK_SKEW <= age <= INIT_DATA_MAX_AGE:
        return None

    try:
        user = json.loads(fields.get("user", ""), object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        return None
    if not isinstance(user, dict):
        return None
    user_id = user.get("id")
    if type(user_id) is not int or not 1 <= user_id <= MAX_TELEGRAM_USER_ID:
        return None
    return {"id": user_id}


def require_telegram_auth(view):
    @wraps(view)
    def protected(*args, **kwargs):
        init_data = request.headers.get("X-Telegram-Init-Data")
        authorization = request.headers.get("Authorization")
        if init_data is not None and authorization is not None:
            return jsonify(error="Send Telegram credentials in a single header."), 401
        if init_data is None and authorization:
            scheme, separator, credential = authorization.partition(" ")
            if separator and scheme.casefold() in {"tma", "bearer"}:
                init_data = credential
        if not init_data:
            return jsonify(error="Open the Mini App from Telegram to sign in."), 401

        user = validate_telegram_init_data(init_data, config.BOT_TOKEN)
        if user is None:
            return jsonify(error="Your session has expired or is invalid. Reopen the Mini App."), 401

        role = db.get_user_role(user["id"])
        if role not in {"admin", "moderator"}:
            return jsonify(error="You don’t have access to submissions."), 403

        g.current_user = user
        g.role = role
        g.is_admin = role == "admin"
        return view(*args, **kwargs)

    return protected


def require_admin(view):
    @require_telegram_auth
    @wraps(view)
    def protected(*args, **kwargs):
        if not g.is_admin:
            return jsonify(error="Only administrators can perform this action."), 403
        return view(*args, **kwargs)

    return protected
