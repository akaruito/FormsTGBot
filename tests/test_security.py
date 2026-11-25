import asyncio
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

from aiogram import Bot, Dispatcher
from aiogram.methods import SendMessage
from aiogram.types import ReplyKeyboardMarkup, Update

TEST_TOKEN = "123456789:" + secrets.token_urlsafe(32)
ADMIN_ID = 10001
MODERATOR_ID = 10002


class FormsSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        boot_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(boot_dir.cleanup)
        with patch.dict(os.environ, {
            "BOT_TOKEN": TEST_TOKEN,
            "FORM_SIGNING_KEY": secrets.token_hex(32),
            "DATABASE_PATH": str(Path(boot_dir.name) / "boot.sqlite"),
            "TRUSTED_HOSTS": "",
            "TRUST_PROXY_HEADERS": "false",
            "ALLOW_UNSAFE_DEV_AUTH": "false",
            "ACTIVE_FORMS_RETENTION_DAYS": "0",
            "DEBUG": "false",
        }):
            cls.server = importlib.import_module("server")
            cls.db = importlib.import_module("db")
        cls.server.app.config["TESTING"] = True

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = str(Path(directory.name) / "test.sqlite")
        patcher = patch.object(self.server.config, "DATABASE_PATH", path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.db.init_db()
        self.assertTrue(self.db.bootstrap_admin(ADMIN_ID))
        self.assertTrue(self.db.add_user(MODERATOR_ID, actor_id=ADMIN_ID))
        self.client = self.server.app.test_client()

    def headers(self, user_id=ADMIN_ID, *, seconds_ago=0):
        fields = {
            "auth_date": str(int(time.time()) - seconds_ago),
            "user": json.dumps({"id": user_id}, separators=(",", ":")),
        }
        canonical = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
        secret = hmac.digest(b"WebAppData", TEST_TOKEN.encode(), hashlib.sha256)
        fields["hash"] = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
        return {"X-Telegram-Init-Data": urlencode(fields)}

    def form_data(self, **values):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        token = re.search(rb'name="form_id"[^>]*value="([^"]+)"', response.data)
        self.assertIsNotNone(token)
        data = {
            "name": "Тестовый клиент",
            "phone": "",
            "email": "test@example.invalid",
            "message": "Проверка формы",
            "form_id": token[1].decode(),
        }
        data.update(values)
        return data

    def create_form(self, **values):
        response = self.client.post("/submit-form", json=self.form_data(**values))
        self.assertEqual(response.status_code, 200)
        return response.json["id"]

    def create_integration(self, origin="https://embedder.example", **values):
        response = self.client.post(
            "/api/admin/api-keys",
            json={"label": "Тестовый сайт", "origin": origin, **values},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        return response.json["key"], response.json["secret"]

    def test_all_current_and_legacy_api_routes_require_auth(self):
        routes = {
            "GET": ["/api/auth/me", "/api/forms", "/api/forms/1", "/api/stats", "/get-forms", "/get-form/1"],
            "PATCH": ["/api/forms/1/viewed"],
            "POST": ["/api/forms/1/restore", "/api/forms/1/toggle-viewed", "/toggle-viewed/1", "/delete-form/1"],
            "DELETE": ["/api/forms/1", "/delete-form/1"],
        }
        for method, paths in routes.items():
            for path in paths:
                with self.subTest(method=method, path=path):
                    response = self.client.open(path, method=method)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_authorized_roles_expiry_and_revocation(self):
        headers = self.headers(MODERATOR_ID)
        response = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["is_admin"])
        self.assertEqual(response.json["role"], "moderator")
        self.assertEqual(self.client.get("/api/forms", headers=self.headers(seconds_ago=1000)).status_code, 401)
        self.assertEqual(self.client.get("/api/forms", headers=self.headers(seconds_ago=-60)).status_code, 401)
        self.assertEqual(
            self.client.get("/api/forms", query_string={"init_data": headers["X-Telegram-Init-Data"]}).status_code,
            401,
        )
        self.assertTrue(self.db.remove_user(MODERATOR_ID, actor_id=ADMIN_ID))
        self.assertEqual(self.client.get("/api/forms", headers=headers).status_code, 403)
        self.assertFalse(self.db.remove_user(ADMIN_ID, actor_id=ADMIN_ID))
        self.db.init_db()
        self.assertFalse(self.db.is_authorized(MODERATOR_ID))

    def test_contact_choices_validation_and_feedback(self):
        email_id = self.create_form()
        phone_id = self.create_form(phone="+7 (999) 000-00-00", email="")
        self.assertEqual(self.db.get_form(email_id)["phone"], "")
        self.assertEqual(self.db.get_form(phone_id)["email"], "")
        values = self.form_data(phone="", email="")
        response = self.client.post("/submit-form", data=values)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Enter a phone number or an email address", response.get_data(as_text=True))
        self.assertIn(values["name"], response.get_data(as_text=True))
        self.assertEqual(self.client.post("/submit-form", json=self.form_data(email="not-an-email")).status_code, 400)
        self.assertEqual(self.client.post("/submit-form", json=self.form_data(message="a" * 4001)).status_code, 400)
        self.assertEqual(self.client.post("/submit-form", data=self.form_data()).status_code, 303)

    def test_submission_retry_and_quota_do_not_duplicate_forms_or_notifications(self):
        payload = self.form_data()
        with patch.object(self.db, "CLIENT_SUBMISSION_LIMIT", 1):
            first = self.client.post("/submit-form", json=payload)
            retry = self.client.post("/submit-form", json=payload)
            self.assertEqual(first.json, retry.json)
            limited = self.client.post("/submit-form", json=self.form_data())
            self.assertEqual(limited.status_code, 429)
            self.assertGreater(int(limited.headers["Retry-After"]), 0)
        self.assertEqual(self.db.get_stats()["total"], 1)
        with self.db.get_db() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM notifications").fetchone()[0], 1)

    def test_listing_redacts_contacts_details_and_uses_cursor(self):
        first = self.create_form()
        newest = self.create_form()
        headers = self.headers(MODERATOR_ID)
        page = self.client.get("/api/forms?limit=1", headers=headers).json
        self.assertEqual(page["next_cursor"], newest)
        self.assertEqual(set(page["items"][0]), {"id", "name", "timestamp", "viewed", "deleted_at"})
        self.assertNotIn("deleted", page["counts"])
        page = self.client.get(f"/api/forms?limit=1&before={newest}", headers=headers).json
        self.assertIsNone(page["next_cursor"])
        self.assertEqual(page["items"][0]["id"], first)
        detail = self.client.get(f"/api/forms/{first}", headers=headers)
        self.assertEqual(detail.json["email"], "test@example.invalid")
        self.assertNotIn("form_id", detail.json)
        self.assertEqual(detail.headers["Cache-Control"], "no-store")

    def test_admin_key_lifecycle_keeps_secret_out_of_list_and_storage(self):
        endpoint = "/api/admin/api-keys"
        self.assertEqual(self.client.get(endpoint).status_code, 401)
        moderator = self.headers(MODERATOR_ID)
        self.assertEqual(self.client.get(endpoint, headers=moderator).status_code, 403)
        self.assertEqual(self.client.post(endpoint, json={}, headers=moderator).status_code, 403)
        key, secret = self.create_integration(origin="https://EMBEDDER.example:443/")
        self.assertEqual(key["origin"], "https://embedder.example")
        self.assertEqual(self.client.delete(f"{endpoint}/{key['id']}", headers=moderator).status_code, 403)
        listed = self.client.get(endpoint, headers=self.headers())
        self.assertEqual(listed.json, {"items": [key]})
        self.assertNotIn(secret, listed.get_data(as_text=True))
        with self.db.get_db() as conn:
            row = conn.execute("SELECT secret_digest FROM api_keys WHERE id = ?", (key["id"],)).fetchone()
            self.assertEqual(row["secret_digest"], hashlib.sha256(secret.split(".")[1].encode("ascii")).digest())
        self.assertEqual(self.client.delete(f"{endpoint}/{key['id']}", headers=self.headers()).status_code, 204)
        self.assertEqual(self.client.delete(f"{endpoint}/{key['id']}", headers=self.headers()).status_code, 204)
        with self.db.get_db() as conn:
            events = conn.execute("SELECT action FROM audit_events WHERE target = ? ORDER BY id", (key["id"],))
            self.assertEqual([event["action"] for event in events], ["create_api_key", "revoke_api_key"])

    def test_integration_api_is_create_only_idempotent_and_rate_limited(self):
        key, secret = self.create_integration()
        headers = {"Authorization": f"Bearer {secret}", "Idempotency-Key": "submission-001"}
        endpoint = "/api/v1/submissions"
        payload = {"name": "Иван", "email": "test@example.invalid", "message": "Тест API"}
        self.assertEqual(self.client.get("/api/forms", headers=headers).status_code, 401)
        self.assertEqual(self.client.get("/api/admin/api-keys", headers=headers).status_code, 401)
        self.assertEqual(self.client.post(endpoint, json=payload, headers=self.headers()).status_code, 401)
        with patch.object(self.db, "INTEGRATION_SUBMISSION_LIMIT", 1):
            first = self.client.post(endpoint, json=payload, headers=headers)
            self.assertEqual(first.status_code, 201)
            self.assertEqual(set(first.json), {"success", "receipt"})
            self.assertRegex(first.json["receipt"], r"^[0-9a-f]{32}$")
            self.assertNotIn("Access-Control-Allow-Origin", first.headers)
            repeated = self.client.post(endpoint, json=payload, headers=headers)
            self.assertEqual(repeated.status_code, 200)
            self.assertEqual(repeated.json, first.json)
            changed = self.client.post(endpoint, json={**payload, "message": "Правка"}, headers=headers)
            self.assertEqual(changed.status_code, 409)
            limited = self.client.post(endpoint, json=payload, headers={**headers, "Idempotency-Key": "submission-002"})
            self.assertEqual(limited.status_code, 429)
            self.assertGreater(int(limited.headers["Retry-After"]), 0)
        self.assertEqual(self.db.get_stats()["total"], 1)
        self.assertEqual(self.client.delete(f"/api/admin/api-keys/{key['id']}", headers=self.headers()).status_code, 204)
        self.assertEqual(self.client.post(endpoint, json=payload, headers=headers).status_code, 401)

    def test_embed_frame_policy_and_signed_submission(self):
        key, secret = self.create_integration()
        path = f"/embed/{key['id']}"
        page = self.client.get(path)
        self.assertEqual(page.status_code, 200)
        self.assertIn(f"frame-ancestors {key['origin']}", page.headers["Content-Security-Policy"])
        self.assertNotIn("X-Frame-Options", page.headers)
        self.assertNotIn(secret, page.get_data(as_text=True))
        self.assertIn(f'action="{path}"', page.get_data(as_text=True))
        token = re.search(rb'name="form_id"[^>]*value="([^"]+)"', page.data)[1].decode()
        payload = {"name": "Иван", "email": "test@example.invalid", "message": "Тест iframe"}
        submitted = self.client.post(path, data={**payload, "form_id": token})
        self.assertEqual(submitted.status_code, 303)
        self.assertEqual(submitted.headers["Location"], f"{path}/success")
        success = self.client.get(submitted.headers["Location"])
        self.assertIn(f"frame-ancestors {key['origin']}", success.headers["Content-Security-Policy"])
        self.assertIn(f'href="{path}"', success.get_data(as_text=True))
        self.assertEqual(self.client.post("/submit-form", data={**payload, "form_id": token}).status_code, 400)
        with patch.object(self.db.time, "time", return_value=key["expires_at"] + 1):
            expired = self.client.get(path)
            self.assertEqual(expired.status_code, 404)
            self.assertIn("frame-ancestors 'none'", expired.headers["Content-Security-Policy"])
            self.assertEqual(self.client.get(f"{path}/success").status_code, 404)
        self.assertEqual(self.client.delete(f"/api/admin/api-keys/{key['id']}", headers=self.headers()).status_code, 204)
        self.assertEqual(self.client.post(path, data={**payload, "form_id": token}).status_code, 404)

    def test_explicit_state_admin_trash_and_restore(self):
        form_id = self.create_form()
        url = f"/api/forms/{form_id}"
        moderator = self.headers(MODERATOR_ID)
        admin = self.headers()
        for _ in range(2):
            response = self.client.patch(f"{url}/viewed", headers=moderator, json={"viewed": True})
            self.assertEqual(response.json, {"success": True, "viewed": True})
        self.assertEqual(self.client.delete(url, headers=moderator).status_code, 403)
        for _ in range(2):
            self.assertEqual(self.client.delete(url, headers=admin).status_code, 200)
        self.assertEqual(self.client.get(url, headers=moderator).status_code, 404)
        self.assertEqual(self.client.get("/api/forms?status=deleted", headers=moderator).status_code, 403)
        trash = self.client.get("/api/forms?status=deleted", headers=admin).json
        self.assertEqual(trash["items"][0]["id"], form_id)
        self.assertEqual(trash["counts"]["deleted"], 1)
        self.assertEqual(self.client.post(f"{url}/restore", headers=moderator).status_code, 403)
        for _ in range(2):
            self.assertEqual(self.client.post(f"{url}/restore", headers=admin).status_code, 200)
        self.assertEqual(self.client.get(url, headers=moderator).json["viewed"], 1)
        with self.db.get_db() as conn:
            actions = [row["action"] for row in conn.execute("SELECT action FROM audit_events ORDER BY id")]
        self.assertEqual(actions.count("mark_viewed"), 1)
        self.assertEqual(actions.count("trash_form"), 1)
        self.assertEqual(actions.count("restore_form"), 1)
        self.assertIsNone(self.db.claim_notification())

    def test_notification_retry_has_exclusive_lease(self):
        self.create_form()
        first = self.db.claim_notification()
        self.assertEqual(first["attempts"], 1)
        self.assertIsNone(self.db.claim_notification())
        self.assertTrue(self.db.finish_notification(first["id"], first["lease_token"], "retry", delay_seconds=30))
        self.assertIsNone(self.db.claim_notification())
        with patch.object(self.db.time, "time", return_value=time.time() + 31):
            again = self.db.claim_notification()
            self.assertEqual(again["id"], first["id"])
            self.assertEqual(again["attempts"], 2)
            self.assertFalse(self.db.finish_notification(first["id"], first["lease_token"], "sent"))
            self.assertTrue(self.db.finish_notification(again["id"], again["lease_token"], "sent"))
        self.assertIsNone(self.db.claim_notification())

    def test_dispatcher_only_exposes_commands_in_private_chats(self):
        bot_module = importlib.import_module("bot")
        dispatcher = Dispatcher()
        dispatcher.include_router(bot_module.router)
        test_url = "https://example.invalid/miniapp"

        def update(user_id, chat, command):
            return Update.model_validate({
                "update_id": 1,
                "message": {
                    "message_id": 1,
                    "date": int(time.time()),
                    "chat": chat,
                    "from": {"id": user_id, "first_name": "Тест", "is_bot": False},
                    "text": command,
                    "entities": [{"type": "bot_command", "offset": 0, "length": len(command)}]
                    if command.startswith("/") else [],
                },
            })

        async def dispatch():
            async with Bot(TEST_TOKEN) as bot:
                with (
                    patch.object(bot_module.config, "WEB_APP_URL", test_url),
                    patch.object(bot.session, "make_request", new_callable=AsyncMock) as transport,
                ):
                    await dispatcher.feed_update(
                        bot, update(ADMIN_ID, {"id": -10001, "type": "group", "title": "Тест"}, "/users")
                    )
                    transport.assert_not_awaited()
                    await dispatcher.feed_update(bot, update(
                        MODERATOR_ID, {"id": MODERATOR_ID, "type": "private", "first_name": "Тест"}, "/start"
                    ))
                    method = transport.await_args.args[1]
                    self.assertIsInstance(method, SendMessage)
                    self.assertEqual(method.reply_markup.inline_keyboard[0][0].web_app.url, test_url)
                    menu = transport.await_args_list[-2].args[1].reply_markup
                    self.assertIsInstance(menu, ReplyKeyboardMarkup)
                    self.assertTrue(menu.is_persistent)
                    self.assertEqual(menu.keyboard[0][0].text, "📋 Submissions")
                    self.assertNotIn(bot_module.API_KEYS_BUTTON, [button.text for row in menu.keyboard for button in row])

                    private = {"id": MODERATOR_ID, "type": "private", "first_name": "Тест"}
                    await dispatcher.feed_update(bot, update(MODERATOR_ID, private, "📋 Заявки"))
                    legacy_reply = transport.await_args.args[1]
                    self.assertEqual(legacy_reply.text, "Submissions")
                    self.assertEqual(legacy_reply.reply_markup.inline_keyboard[0][0].web_app.url, test_url)

                    for user_id, allowed in ((MODERATOR_ID, False), (ADMIN_ID, True)):
                        private = {"id": user_id, "type": "private", "first_name": "Тест"}
                        await dispatcher.feed_update(bot, update(user_id, private, "/api_keys"))
                        markup = transport.await_args.args[1].reply_markup
                        if allowed:
                            self.assertEqual(markup.inline_keyboard[0][0].web_app.url, f"{test_url}?panel=integrations")
                        else:
                            self.assertIsInstance(markup, ReplyKeyboardMarkup)

        asyncio.run(dispatch())

    def test_notification_contains_only_reference_and_checks_current_role(self):
        worker = importlib.import_module("notifications")
        new_admin_id = 10003
        self.assertTrue(self.db.add_user(new_admin_id, is_admin_flag=1, actor_id=ADMIN_ID))
        form_id = self.create_form()
        self.assertTrue(self.db.remove_user(new_admin_id, actor_id=ADMIN_ID))
        bot = AsyncMock(spec=Bot)

        async def deliver():
            for _ in range(2):
                job = self.db.claim_notification()
                self.assertIsNotNone(job)
                await worker.deliver_notification(bot, job, "https://example.invalid/miniapp")

        asyncio.run(deliver())
        bot.send_message.assert_awaited_once()
        sent = bot.send_message.await_args.kwargs
        self.assertEqual(sent["chat_id"], ADMIN_ID)
        self.assertEqual(sent["text"], f"New submission #{form_id}")
        self.assertTrue(sent["protect_content"])

    def test_expiration_prunes_trash_and_can_prune_active_records(self):
        active_id = self.create_form()
        deleted_id = self.create_form()
        self.assertTrue(self.db.delete_form(deleted_id, ADMIN_ID))
        with self.db.get_db(write=True) as conn:
            conn.execute("UPDATE forms SET timestamp = '2020-01-01' WHERE id = ?", (active_id,))
            conn.execute("UPDATE forms SET deleted_at = '2020-01-01' WHERE id = ?", (deleted_id,))
        self.assertEqual(self.db.prune_expired(), 1)
        self.assertIsNotNone(self.db.get_form(active_id))
        self.assertIsNone(self.db.get_form(deleted_id, include_deleted=True))
        with patch.object(self.server.config, "ACTIVE_FORMS_RETENTION_DAYS", 1):
            self.assertEqual(self.db.prune_expired(), 1)
        self.assertIsNone(self.db.get_form(active_id))
        self.assertIsNone(self.db.claim_notification())

    def test_legacy_migration_preserves_contacts_under_parallel_startup(self):
        path = Path(self.server.config.DATABASE_PATH).with_name("legacy.sqlite")
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute(
                "CREATE TABLE forms (id INTEGER PRIMARY KEY, name TEXT, email_or_phone TEXT, "
                "message TEXT, timestamp TEXT, viewed INTEGER)"
            )
            conn.executemany(
                "INSERT INTO forms VALUES (?, 'name', ?, 'message', '2025-04-01', 0)",
                [(1, "test@example.invalid"), (2, "+12345678901")],
            )
        with patch.object(self.server.config, "DATABASE_PATH", str(path)):
            with ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(lambda _index: self.db.init_db(), range(3)))
            self.assertEqual(self.db.get_form(1)["email"], "test@example.invalid")
            self.assertEqual(self.db.get_form(2)["phone"], "+12345678901")
            self.assertEqual(self.db.get_stats()["total"], 2)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_schema_v1_migration_keeps_existing_access_and_forms(self):
        path = Path(self.server.config.DATABASE_PATH).with_name("version-one.sqlite")
        with patch.object(self.server.config, "DATABASE_PATH", str(path)):
            with self.db.get_db(write=True) as conn:
                self.db._migrate_original_schema(conn)
                conn.execute("PRAGMA user_version = 1")
                conn.execute("INSERT INTO users (user_id, is_admin) VALUES (?, 0)", (str(MODERATOR_ID),))
                conn.execute("INSERT INTO forms (name, message, timestamp) VALUES ('Иван', 'Тест', '2025-01-01')")
            self.db.init_db()
            self.assertEqual(self.db.get_user_role(MODERATOR_ID), "moderator")
            self.assertEqual(self.db.get_form(1)["message"], "Тест")
            self.assertTrue(self.db.bootstrap_admin(ADMIN_ID))
            self.assertIn("id", self.db.create_api_key("Тест", "https://embedder.example", 90, ADMIN_ID)[0])

    def test_static_assets_and_public_response_headers(self):
        for path in ("/", "/success", "/miniapp.html"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'<html lang="en">', response.data)
            self.assertNotIn("unsafe-inline", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(self.client.get("/nginx-site").status_code, 404)


if __name__ == "__main__":
    unittest.main()
