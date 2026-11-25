# Forms Telegram Bot

The public contact form saves submissions in SQLite. Moderators can read submissions and change their viewed status in the Telegram Mini App. Administrators can also manage moderators and API keys, move submissions to the trash, and restore them.

## Local setup

Use Python 3.14.10 or a later patch release in the 3.14 series and uv. Install the locked dependencies and create a local configuration.

```sh
uv sync --locked --no-dev
test -e .env || (umask 077 && cp .env.example .env)
chmod 600 .env
.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Set `FORM_SIGNING_KEY` in `.env` to the generated value. Store it separately from the database and backups. You can test the public form without a Telegram bot token.

```sh
.venv/bin/python -m server
```

Open `http://127.0.0.1:5000/` to view the form. The local database defaults to `var/forms.db`. If you already have a legacy `forms.db` in the project root, set `DATABASE_PATH` to its absolute path.

To test the Mini App, set `BOT_TOKEN` to your test bot’s token and `WEB_APP_URL` to the app’s public HTTPS URL, such as `https://forms.example.com/miniapp`. Replace the example ID with your numeric Telegram ID. After creating the first administrator, start the bot and the notification worker in separate terminals.

```sh
.venv/bin/python -m bot bootstrap-admin 123456789
.venv/bin/python -m bot
.venv/bin/python -m notifications
```

Send `/start` in a private chat with the bot to show the bottom menu for your role. Select **Submissions** to get the button that opens the Mini App. Administrators also have **Moderators** and **API keys**. Use `/add_moderator ID` to grant access, `/remove_moderator ID` to revoke it, and `/moderators` to list moderators. The legacy commands `/add_user ID` and `/remove_user ID` work for moderators. The `bootstrap-admin` command creates the first administrator when there are no others. Existing administrators keep their access after an upgrade, and existing operators become moderators. Notification recipients must start a private chat with the bot.

## Embed a form on another website

1. In a private chat, select **API keys**, then **Manage API keys**. Create a key with a name, the website’s exact HTTPS address, and an expiration period. For example, `https://example.com` and `https://www.example.com` are different addresses. Include the port if it differs from the HTTPS default. Keys expire after 90 days by default.
2. Copy the iframe HTML from the active key’s card. Forms Telegram Bot serves the form and uses `Content-Security-Policy: frame-ancestors` to allow embedding on the specified website. The form URL is public and can be opened directly. Keep the secret key on the integration server.
3. Revoking a key or letting it expire disables both the iframe and server API submissions. To rotate a key, create a replacement, update the iframe code and the server secret, and then revoke the old key. The API keys screen shows the secret once, when you create it.

If the form and Mini App use different domains, the Mini App domain must also proxy `/embed/`, `/static/`, and `/api/` to Flask. The included Nginx configuration forwards these routes.

### Submit from the integration server

If the third-party site renders its own form, its server sends JSON to `POST /api/v1/submissions`. Store the secret in the server environment. The visitor’s browser submits the form to the third-party site’s server. The browser enforces iframe restrictions, and the API verifies the secret key.

```http
POST /api/v1/submissions HTTP/1.1
Host: forms.example.com
Authorization: Bearer <secret_key>
Content-Type: application/json
Idempotency-Key: 574c59c2-17e8-4b15-9bfa-ab44caeea17e

{"name":"Alex Morgan","email":"alex@example.com","message":"Please get back to me."}
```

Send `name`, `message`, and at least one of `phone` or `email`. Generate a new `Idempotency-Key` for each new submission using 8 to 128 ASCII characters from `A–Z a–z 0–9 . _ ~ -`. After a network error, retry with the same key and payload. The server returns `201` for a new submission and `200` for a retry, both with the same `receipt`. It returns `409` if the same idempotency key is used with different data, `401` for an invalid API key, and `429` with `Retry-After` when the rate limit is exceeded. The notification worker removes idempotency records after 24 hours. An API key only grants permission to create submissions. Disable logging of response bodies and authorization headers on the proxy that serves the API and the key management screen.

## Tests

```sh
uv run --locked python -m unittest discover -s tests -v
```

## Deployment

These steps are for Linux with systemd and Nginx. Windows deployment has not been tested.

1. Place the code in `/opt/forms-tgbot`. The system administrator should own the code and virtual environment. Create a dedicated system user and group named `forms-tgbot` for all three services. If uv manages Python, install it in a directory accessible to the services and outside users’ home directories. For example, set `UV_PYTHON_INSTALL_DIR=/opt/forms-tgbot/.uv-python`. Run `uv sync --locked --no-dev` and make sure the `forms-tgbot` user can access Python in `.venv`.
2. Create `/etc/forms-tgbot/environment` with permissions `0600`. Set `FORM_SIGNING_KEY`, `BOT_TOKEN`, `WEB_APP_URL`, `DATABASE_PATH=/var/lib/forms-tgbot/forms.db`, `TRUSTED_HOSTS=forms.example.com`, and `TRUST_PROXY_HEADERS=true`. Use your own domain. All three services must use the same absolute SQLite path. Restrict access to the SQLite files, including write-ahead logs and backups.
3. Before upgrading, stop all three processes, back up SQLite, and run `sqlite3 /path/to/backup.sqlite 'PRAGMA integrity_check;'`. Before starting the new version, place your existing database at `DATABASE_PATH`, set its owner to `forms-tgbot`, and set permissions to `0600`. The application migrates the schema on startup. Check administrator access in a private chat with the bot after the migration.
4. Copy the [web service unit](deploy/forms-web.service) and [background service template](deploy/forms-worker@.service) to `/etc/systemd/system`. For a new database, create the first administrator before exposing the site. Use the same `DATABASE_PATH` and run the command as `forms-tgbot` with a restrictive umask. Replace the example ID with your numeric Telegram ID.

   ```sh
   sudo install -d -m 0700 -o forms-tgbot -g forms-tgbot /var/lib/forms-tgbot
   sudo -u forms-tgbot env DATABASE_PATH=/var/lib/forms-tgbot/forms.db \
       sh -c 'cd /opt/forms-tgbot && umask 077 && exec .venv/bin/python -m bot bootstrap-admin "$1"' bootstrap 123456789
   sudo systemctl daemon-reload
   sudo systemctl enable --now forms-web.service forms-worker@bot.service forms-worker@notifications.service
   ```

   Gunicorn listens on `127.0.0.1:5000`. Restrict access to this port to processes on the same server.
5. Install Nginx with current security fixes. In the [Nginx configuration](deploy/nginx-site.conf), replace the domain and TLS certificate paths, include the file in the `http` block, and run `nginx -t`. The template forwards the form, Mini App, and API routes to Flask. It terminates TLS and replaces proxy headers sent by clients. If there is another proxy in front of Nginx, configure its trusted addresses separately in Nginx. [Nginx security advisories](https://nginx.org/en/security_advisories.html)
6. Over HTTPS, verify the home page, the redirect after form submission, and a `401` response from `/api/forms` when signed out. With a test user, open the Mini App from a private Telegram chat and check the submissions list, viewed status, trash, and restore. Also verify sign-in directly in the Telegram client. [Telegram Mini Apps documentation](https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app)

Store backups and logs in a restricted directory. When `ACTIVE_FORMS_RETENTION_DAYS` is set to a positive value, the worker permanently removes active submissions older than that number of days. The default of `0` disables automatic removal of active submissions. The worker clears the trash and completed notifications after 30 days and audit records after 90 days. Set backup retention separately.

The notification worker removes expired data and retries temporary delivery failures. It sends only the submission number and a button to open the Mini App in a private chat. When upgrading, review older logs and notifications for contact details before deciding what to retain. Mini App authentication lasts 15 minutes from launch. Reopen the app from the bot when it expires.

## Compatibility

Flask must serve the public form HTML so the browser receives a signed submission identifier. The legacy `GET /get-forms` endpoint returns a page of submission summaries. Use the `X-Next-Cursor` header to request the next page. The legacy `POST /toggle-viewed/<id>` endpoint accepts an explicit JSON status such as `{"viewed":true}`, so retrying the request keeps the same status.
