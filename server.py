import hashlib
import hmac
import ipaddress
import logging
import re
import sqlite3
from unicodedata import category
from uuid import uuid4

from flask import Flask, abort, g, jsonify, redirect, render_template, request, url_for
from itsdangerous import BadData, URLSafeTimedSerializer
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.routing import BaseConverter, ValidationError

import config
import db
from auth import require_admin, require_telegram_auth


logger = logging.getLogger(__name__)
FIELD_LIMITS = {"name": 120, "phone": 32, "email": 254, "message": 4000}
FORM_TOKEN_MAX_AGE = 2 * 60 * 60
# An HTML form can percent-encode a four-byte UTF-8 character as 12 bytes.
MAX_BODY_BYTES = config.MAX_FORM_BODY_BYTES
SQLITE_MAX_ID = (1 << 63) - 1
CURSOR_PATTERN = re.compile(r"[1-9][0-9]{0,18}")
FORM_NONCE_PATTERN = re.compile(r"[0-9a-f]{32}")
PHONE_PATTERN = re.compile(r"\+?[0-9 ().-]+")
EMAIL_LOCAL = re.compile(r"[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*")
EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
FORM_STATUSES = {"all", "new", "viewed", "deleted"}
INTEGRATION_ID = r"[A-Za-z0-9_-]{24}"
API_KEY = re.compile(rf"fsk_({INTEGRATION_ID})\.([A-Za-z0-9_-]{{43}})")
IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._~-]{8,128}")
HTTPS_ORIGIN = re.compile(r"https://([a-z0-9.-]{1,253})(?::([0-9]{1,5}))?/?", re.ASCII | re.IGNORECASE)
API_KEY_FIELDS = ("id", "label", "origin", "created_at", "expires_at", "revoked_at")


class RecordIdConverter(BaseConverter):
    regex = r"[1-9][0-9]{0,18}"

    def to_python(self, value):
        number = int(value)
        if number > SQLITE_MAX_ID:
            raise ValidationError()
        return number


class IntegrationIdConverter(BaseConverter):
    regex = INTEGRATION_ID


app = Flask(__name__, template_folder="Web", static_folder="Web/static", static_url_path="/static")
app.url_map.converters["record_id"] = RecordIdConverter
app.url_map.converters["integration_id"] = IntegrationIdConverter
app.config.from_mapping(
    MAX_CONTENT_LENGTH=MAX_BODY_BYTES,
    MAX_FORM_MEMORY_SIZE=MAX_BODY_BYTES,
    MAX_FORM_PARTS=8,
    TRUSTED_HOSTS=config.TRUSTED_HOSTS or None,
)
if config.TRUST_PROXY_HEADERS:
    direct_request = app.wsgi_app
    proxy_request = ProxyFix(direct_request, x_for=1, x_proto=1)

    def trusted_proxy_only(environ, start_response):
        handler = proxy_request if environ.get("REMOTE_ADDR") in {"127.0.0.1", "::1"} else direct_request
        return handler(environ, start_response)

    app.wsgi_app = trusted_proxy_only

form_secret = config.require_secret()
if config.BOT_TOKEN:
    config.require_bot_token()
form_tokens = URLSafeTimedSerializer(
    form_secret,
    salt="contact-form-v1",
    signer_kwargs={"digest_method": hashlib.sha256},
)
client_hash_key = hmac.digest(form_secret.encode(), b"submission-rate-limit-v1", hashlib.sha256)
db.init_db()


@app.after_request
def security_headers(response):
    mini_app = request.endpoint == "miniapp"
    embed_origin = g.get("embed_origin")
    ancestors = "'self' https://web.telegram.org" if mini_app else embed_origin or "'none'"
    policy = [
        "default-src 'none'",
        "base-uri 'none'",
        "object-src 'none'",
        "form-action 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "script-src 'self'" + (" https://telegram.org/js/telegram-web-app.js" if mini_app else ""),
        "frame-ancestors " + ancestors,
    ]
    response.headers["Content-Security-Policy"] = "; ".join(policy)
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not mini_app and not embed_origin:
        response.headers["X-Frame-Options"] = "DENY"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response


def _form_page(status=200, *, values=None, token=None, error=None, field_errors=None, key_id=None):
    if token is None:
        nonce = uuid4().hex
        token = form_tokens.dumps(f"{key_id}:{nonce}" if key_id else nonce)
    return render_template(
        "index.html",
        form_id=token,
        form_action=url_for("embed_form", key_id=key_id) if key_id else url_for("submit_form"),
        values=values or {},
        error=error,
        field_errors=field_errors or {},
    ), status


def _wants_json():
    return request.is_json or request.accept_mimetypes.best_match(
        ["text/html", "application/json"]
    ) == "application/json"


def _form_error(status, message, *, values=None, token=None, field_errors=None, key_id=None):
    if key_id is None and _wants_json():
        return jsonify(error=message, field_errors=field_errors or {}), status
    return _form_page(
        status, values=values, token=token, error=message, field_errors=field_errors, key_id=key_id,
    )


def _api_error(status, message):
    return jsonify(error=message), status


def _json_object():
    try:
        payload = request.get_json(silent=True)
    except RecursionError:
        return None
    return payload if isinstance(payload, dict) else None


def _validate_contact_email(email):
    local, separator, domain = email.rpartition("@")
    labels = domain.split(".")
    return (
        separator and len(local) <= 64 and EMAIL_LOCAL.fullmatch(local)
        and len(labels) >= 2 and all(EMAIL_DOMAIN.fullmatch(label) for label in labels)
    )


def _form_values(source):
    values = {}
    errors = {}
    for field, limit in FIELD_LIMITS.items():
        value = source.get(field, "")
        if not isinstance(value, str):
            errors[field] = "Enter a text value."
            continue
        value = value.strip()
        if any(
            category(ch) in {"Cc", "Cs"} and not (field == "message" and ch in "\r\n\t")
            for ch in value
        ):
            errors[field] = "Remove any unsupported characters from this field."
            continue
        values[field] = value[:limit]
        if len(value) > limit:
            errors[field] = f"Enter no more than {limit} characters."

    for field in ("name", "message"):
        if not values.get(field) and field not in errors:
            errors[field] = "Fill in this field."

    phone = values.get("phone", "")
    email = values.get("email", "")
    if not (phone or email or "phone" in errors or "email" in errors):
        errors["contact"] = "Enter a phone number or an email address."
    if phone and "phone" not in errors and (
        not PHONE_PATTERN.fullmatch(phone) or not 7 <= sum(ch.isdecimal() for ch in phone) <= 15
    ):
        errors["phone"] = "Enter a phone number with 7 to 15 digits."
    if email and "email" not in errors and not _validate_contact_email(email):
        errors["email"] = "Enter a valid email address."

    return values, errors


def _client_key():
    try:
        address = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        network = "unknown"
    else:
        if isinstance(address, ipaddress.IPv6Address):
            mapped = address.ipv4_mapped
            network = str(mapped) if mapped else str(ipaddress.ip_network((address, 64), strict=False))
        else:
            network = str(address)
    return hmac.new(client_hash_key, network.encode(), hashlib.sha256).hexdigest()


def _form_nonce(token, key_id=None):
    if not isinstance(token, str) or len(token) > 256:
        return None
    try:
        nonce = form_tokens.loads(token, max_age=FORM_TOKEN_MAX_AGE)
    except BadData:
        return None
    if not isinstance(nonce, str):
        return None
    if key_id:
        scoped_id, separator, value = nonce.partition(":")
        return nonce if separator and scoped_id == key_id and FORM_NONCE_PATTERN.fullmatch(value) else None
    return nonce if FORM_NONCE_PATTERN.fullmatch(nonce) else None


def _save_contact(values, nonce, *, key_id=None, key_secret=None):
    return db.submit_form(
        values["name"], values["phone"], values["email"], values["message"], nonce, _client_key(),
        integration_id=key_id, key_secret=key_secret,
    )


def _origin(value):
    if not isinstance(value, str) or len(value) > 268:
        return None
    match = HTTPS_ORIGIN.fullmatch(value.strip())
    if match is None:
        return None
    host, port = match.groups()
    host = host.lower()
    labels = host.split(".")
    if len(labels) < 2 or not labels[-1][:1].isalpha() or not all(EMAIL_DOMAIN.fullmatch(label) for label in labels):
        return None
    port = int(port) if port else 443
    if not 1 <= port <= 65535:
        return None
    return f"https://{host}" if port == 443 else f"https://{host}:{port}"


def _require_embed(key_id):
    record = db.get_active_api_key(key_id)
    origin = _origin(record["origin"]) if record else None
    if origin is None:
        abort(404)
    g.embed_origin = origin


@app.get("/")
def index():
    return _form_page()


@app.post("/submit-form")
def submit_form():
    return _submit_contact()


def _submit_contact(key_id=None):
    if key_id and request.headers.get("Sec-Fetch-Site") in {"cross-site", "same-site"}:
        return _form_error(403, "Submit your message from the open form.", key_id=key_id)

    if key_id is None and request.is_json:
        source = _json_object()
        if source is None:
            return _form_error(400, "Send the form data as a JSON object.")
    elif request.mimetype in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        source = request.form
    else:
        return _form_error(415, "Unsupported form format.", key_id=key_id)

    values, errors = _form_values(source)
    token = source.get("form_id")
    nonce = _form_nonce(token, key_id)
    if nonce is None:
        return _form_error(
            400, "The form has expired. Review your entries and submit it again.",
            values=values, field_errors=errors, key_id=key_id,
        )
    if errors:
        return _form_error(
            400, "Check the form fields.", values=values, token=token, field_errors=errors,
            key_id=key_id,
        )

    try:
        form_id, created = _save_contact(values, nonce, key_id=key_id)
    except db.IntegrationUnavailable:
        g.pop("embed_origin", None)
        abort(404)
    except db.FormTokenConflict:
        return _form_error(
            409, "This form was already submitted. Review your entries before submitting again.",
            values=values, key_id=key_id,
        )
    except db.SubmissionRateLimited as error:
        body, status = _form_error(
            429, "Too many submissions. Try again later.", values=values, token=token,
            key_id=key_id,
        )
        return body, status, {"Retry-After": str(error.retry_after)}
    except sqlite3.Error as error:
        logger.error("Could not save form: %s", type(error).__name__)
        return _form_error(
            503, "The service is temporarily unavailable. Try again later.", values=values, token=token, key_id=key_id,
        )

    if created:
        logger.info("Form %s saved", form_id)
    if key_id:
        return redirect(url_for("embed_success", key_id=key_id), code=303)
    if _wants_json():
        return jsonify(success=True, id=form_id)
    return redirect(url_for("success"), code=303)


@app.get("/success")
def success():
    return render_template("sendsuccess.html")


@app.route("/embed/<integration_id:key_id>", methods=["GET", "POST"])
def embed_form(key_id):
    _require_embed(key_id)
    if request.method == "POST":
        return _submit_contact(key_id)
    return _form_page(key_id=key_id)


@app.get("/embed/<integration_id:key_id>/success")
def embed_success(key_id):
    _require_embed(key_id)
    return render_template("sendsuccess.html", return_url=url_for("embed_form", key_id=key_id))


def _invalid_submission_key():
    return (
        jsonify(error="A valid API key is required to submit forms."),
        401,
        {"WWW-Authenticate": 'Bearer realm="forms"'},
    )


@app.post("/api/v1/submissions")
def submit_integration_form():
    scheme, separator, credential = request.headers.get("Authorization", "").partition(" ")
    match = API_KEY.fullmatch(credential) if separator and scheme.casefold() == "bearer" else None
    if match is None:
        return _invalid_submission_key()
    key_id, secret = match.groups()
    if not db.is_api_key_authorized(key_id, secret):
        return _invalid_submission_key()

    idempotency_key = request.headers.get("Idempotency-Key", "")
    if not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        return _api_error(400, "Send a valid Idempotency-Key header.")
    if request.mimetype != "application/json":
        return _api_error(415, "Use application/json as the Content-Type.")
    payload = _json_object()
    if payload is None:
        return _api_error(400, "Send the form data as a JSON object.")

    values, errors = _form_values(payload)
    if errors:
        return jsonify(error="Check the form fields.", field_errors=errors), 400

    digest = hashlib.sha256(f"api-submission-v1:{key_id}:{idempotency_key}".encode("ascii")).hexdigest()
    try:
        _, created = _save_contact(values, digest, key_id=key_id, key_secret=secret)
    except db.IntegrationUnavailable:
        return _invalid_submission_key()
    except db.FormTokenConflict:
        return _api_error(409, "This Idempotency-Key was already used with different data.")
    except db.SubmissionRateLimited as error:
        return jsonify(error="Too many submissions. Try again later."), 429, {
            "Retry-After": str(error.retry_after),
        }

    return jsonify(success=True, receipt=digest[:32]), 201 if created else 200


@app.get("/miniapp.html")
@app.get("/miniapp")
def miniapp():
    return render_template("miniapp.html")


@app.get("/api/auth/me")
@require_telegram_auth
def auth_me():
    return jsonify(authenticated=True, user=g.current_user, is_admin=g.is_admin, role=g.role)


def _key_metadata(record):
    return {field: record[field] for field in API_KEY_FIELDS}


@app.get("/api/admin/api-keys")
@require_admin
def list_api_keys():
    return jsonify(items=[_key_metadata(record) for record in db.list_api_keys(g.current_user["id"])])


@app.post("/api/admin/api-keys")
@require_admin
def create_api_key():
    payload = _json_object()
    if payload is None:
        return _api_error(400, "Send the key settings as a JSON object.")

    label = payload.get("label")
    if not isinstance(label, str) or not 1 <= len(label.strip()) <= 80 or any(
        category(character) in {"Cc", "Cf", "Cs"} for character in label
    ):
        return _api_error(400, "Enter a key name between 1 and 80 characters.")

    origin = _origin(payload.get("origin"))
    if origin is None:
        return _api_error(400, "Enter the website’s exact HTTPS address without a path, such as https://example.com.")

    days = payload.get("expires_days", 90)
    if type(days) is not int or not 1 <= days <= 365:
        return _api_error(400, "The key must expire in 1 to 365 days.")

    try:
        record, secret = db.create_api_key(label.strip(), origin, days, g.current_user["id"])
    except db.ApiKeyLimit:
        return _api_error(409, "You’ve reached the integration key limit.")
    return jsonify(key=_key_metadata(record), secret=secret), 201


@app.delete("/api/admin/api-keys/<integration_id:key_id>")
@require_admin
def revoke_api_key(key_id):
    if not db.revoke_api_key(key_id, g.current_user["id"]):
        return _api_error(404, "Key not found.")
    return "", 204


@app.get("/get-forms")
@app.get("/api/forms")
@require_telegram_auth
def get_forms():
    status = request.args.get("status", "all")
    if status not in FORM_STATUSES:
        return _api_error(400, "Unknown submission filter.")
    if status == "deleted" and not g.is_admin:
        return _api_error(403, "Only administrators can access the trash.")

    cursor = request.args.get("before")
    if cursor is not None and (not CURSOR_PATTERN.fullmatch(cursor) or int(cursor) > SQLITE_MAX_ID):
        return _api_error(400, "Invalid pagination cursor.")

    raw_limit = request.args.get("limit", "25")
    if not re.fullmatch(r"[0-9]{1,2}", raw_limit) or not 1 <= int(raw_limit) <= 50:
        return _api_error(400, "Page size must be between 1 and 50.")

    page = db.get_form_page(
        status, int(cursor) if cursor is not None else None, int(raw_limit), include_deleted=g.is_admin,
    )
    if request.path == "/get-forms":
        response = jsonify(page["items"])
        if page["next_cursor"] is not None:
            response.headers["X-Next-Cursor"] = str(page["next_cursor"])
        return response
    return jsonify(page)


@app.get("/get-form/<record_id:form_id>")
@app.get("/api/forms/<record_id:form_id>")
@require_telegram_auth
def get_form(form_id):
    form = db.get_form(form_id, include_deleted=g.is_admin)
    if form is None:
        return _api_error(404, "Submission not found.")
    return jsonify(form)


@app.post("/toggle-viewed/<record_id:form_id>")
@app.post("/api/forms/<record_id:form_id>/toggle-viewed")
@app.patch("/api/forms/<record_id:form_id>/viewed")
@require_telegram_auth
def set_viewed(form_id):
    payload = _json_object()
    if payload is None or type(payload.get("viewed")) is not bool:
        return _api_error(400, "Set viewed to true or false.")

    viewed = payload["viewed"]
    if not db.set_viewed(form_id, viewed, g.current_user["id"]):
        return _api_error(404, "Active submission not found.")
    return jsonify(success=True, viewed=viewed)


@app.route("/delete-form/<record_id:form_id>", methods=["POST", "DELETE"])
@app.delete("/api/forms/<record_id:form_id>")
@require_telegram_auth
def delete_form(form_id):
    if not g.is_admin:
        return _api_error(403, "Only administrators can delete submissions.")
    if not db.delete_form(form_id, g.current_user["id"]):
        return _api_error(404, "Submission not found.")
    return jsonify(success=True)


@app.post("/api/forms/<record_id:form_id>/restore")
@require_telegram_auth
def restore_form(form_id):
    if not g.is_admin:
        return _api_error(403, "Only administrators can restore submissions.")
    if not db.restore_form(form_id, g.current_user["id"]):
        return _api_error(404, "Submission not found.")
    return jsonify(success=True)


@app.get("/api/stats")
@require_telegram_auth
def stats():
    return jsonify(db.get_stats(include_deleted=g.is_admin))


@app.errorhandler(db.PermissionDenied)
def access_denied(_error):
    return _api_error(403, "You don’t have permission to perform this action.")


@app.errorhandler(sqlite3.Error)
def database_error(error):
    logger.error("Database operation failed: %s", type(error).__name__)
    return _api_error(503, "The service is temporarily unavailable. Try again later.")


@app.errorhandler(HTTPException)
def http_error(error):
    if request.endpoint == "submit_form" and error.code == 413:
        return _form_error(413, "The request is too large. Shorten your message.")
    if request.endpoint == "embed_form" and error.code == 413 and g.get("embed_origin"):
        return _form_error(
            413, "The request is too large. Shorten your message.", key_id=request.view_args["key_id"],
        )
    if request.path.startswith("/api/") or request.path == "/get-forms" or request.path.startswith(
        ("/get-form/", "/toggle-viewed/", "/delete-form/"),
    ):
        response = error.get_response()
        response.set_data(app.json.dumps({"error": error.name}))
        response.content_type = "application/json"
        return response
    return error


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=False, use_reloader=False)
