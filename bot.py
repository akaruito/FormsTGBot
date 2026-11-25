import argparse
import asyncio
import logging
from urllib.parse import parse_qsl, urlencode, urlsplit

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ChatType
from aiogram.exceptions import AiogramError
from aiogram.filters import Command, CommandObject, CommandStart

import config
import db

logger = logging.getLogger(__name__)
router = Router()
router.message.filter(F.chat.type == ChatType.PRIVATE, F.from_user)

USERS_PER_PAGE = 20
FORMS_BUTTON = "📋 Submissions"
STATS_BUTTON = "📊 Statistics"
MODERATORS_BUTTON = "👥 Moderators"
API_KEYS_BUTTON = "🔑 API keys"
MODERATOR_COMMANDS = (
    "/add_moderator ID — Grant access to submissions.\n"
    "/remove_moderator ID — Revoke access."
)


def bottom_keyboard(role: str) -> types.ReplyKeyboardMarkup:
    keyboard = [[types.KeyboardButton(text=label) for label in (FORMS_BUTTON, STATS_BUTTON)]]
    if role == "admin":
        keyboard.append([types.KeyboardButton(text=label) for label in (MODERATORS_BUTTON, API_KEYS_BUTTON)])
    return types.ReplyKeyboardMarkup(keyboard=keyboard, resize_keyboard=True, is_persistent=True)


def web_app_keyboard(*, integrations: bool = False) -> types.InlineKeyboardMarkup:
    url = urlsplit(config.require_web_app_url())
    query = [(key, value) for key, value in parse_qsl(url.query, keep_blank_values=True) if key != "panel"]
    if integrations:
        query.append(("panel", "integrations"))
    return types.InlineKeyboardMarkup(inline_keyboard=[[
        types.InlineKeyboardButton(
            text="Manage API keys" if integrations else "📋 Open submissions",
            web_app=types.WebAppInfo(url=url._replace(query=urlencode(query)).geturl()),
        ),
    ]])


async def deny_access(message: types.Message, role: str | None) -> None:
    if role == "moderator":
        await message.reply("⛔ Only administrators can use this.", reply_markup=bottom_keyboard(role))
    else:
        await message.reply("⛔ Access denied.", reply_markup=types.ReplyKeyboardRemove())


async def require_admin(message: types.Message) -> bool:
    role = db.get_user_role(message.from_user.id)
    if role == "admin":
        return True
    await deny_access(message, role)
    return False


@router.message(CommandStart())
async def start_command(message: types.Message):
    user_id = message.from_user.id
    role = db.get_user_role(user_id)
    if role not in {"moderator", "admin"}:
        await message.reply(
            f"⛔ Access denied. Your Telegram ID is {user_id}. "
            "Contact an administrator for access to submissions.",
            reply_markup=types.ReplyKeyboardRemove(),
        )
        return

    role_name = "Administrator" if role == "admin" else "Moderator"
    await message.reply(
        f"Role: {role_name}.",
        reply_markup=bottom_keyboard(role),
        protect_content=True,
    )
    await message.reply("Submissions", reply_markup=web_app_keyboard(), protect_content=True)


# Telegram clients can keep the previous reply keyboard until the next /start.
@router.message(F.text.in_({FORMS_BUTTON, "📋 Заявки"}))
@router.message(Command("forms"))
async def open_forms(message: types.Message):
    if not db.is_authorized(message.from_user.id):
        await deny_access(message, None)
        return
    await message.reply("Submissions", reply_markup=web_app_keyboard(), protect_content=True)


@router.message(F.text.in_({API_KEYS_BUTTON, "🔑 API-ключи"}))
@router.message(Command("api_keys"))
async def open_api_keys(message: types.Message):
    if not await require_admin(message):
        return
    await message.reply("API keys", reply_markup=web_app_keyboard(integrations=True), protect_content=True)


@router.message(Command("help"))
async def help_command(message: types.Message):
    role = db.get_user_role(message.from_user.id)
    if role not in {"moderator", "admin"}:
        await deny_access(message, None)
        return

    text = "/forms — Open submissions.\n/stats — View submission statistics."
    if role == "admin":
        text += (
            "\n/moderators [page] — List moderators."
            f"\n{MODERATOR_COMMANDS}"
            "\n/api_keys — Manage API keys."
        )
    await message.reply(text, reply_markup=bottom_keyboard(role), protect_content=True)


@router.message(F.text.in_({STATS_BUTTON, "📊 Статистика"}))
@router.message(Command("stats"))
async def stats_command(message: types.Message):
    if not db.is_authorized(message.from_user.id):
        await deny_access(message, None)
        return

    stats = db.get_stats()
    await message.reply(
        f"📊 Submission statistics\n"
        f"Total: {stats['total']}\n"
        f"New: {stats['unviewed']}\n"
        f"Viewed: {stats['viewed']}",
        protect_content=True,
    )


@router.message(F.text.in_({MODERATORS_BUTTON, "👥 Модераторы", "👥 Список пользователей"}))
@router.message(Command("moderators", "users"))
async def list_moderators(message: types.Message, command: CommandObject | None = None):
    if not await require_admin(message):
        return

    page_arg = ((command.args or "").strip() if command else "") or "1"
    page = int(page_arg) if len(page_arg) <= 10 and page_arg.isascii() and page_arg.isdecimal() else 0
    if not 1 <= page <= 2**31:
        await message.reply("Enter a page number, such as /moderators 2.")
        return

    try:
        moderators = db.get_moderators(
            limit=USERS_PER_PAGE + 1,
            offset=(page - 1) * USERS_PER_PAGE,
            actor_id=message.from_user.id,
        )
    except db.PermissionDenied:
        await deny_access(message, db.get_user_role(message.from_user.id))
        return

    lines = [f"Moderators · Page {page}"]
    if moderators:
        lines.extend(str(user["user_id"]) for user in moderators[:USERS_PER_PAGE])
    else:
        lines.append("No moderators on this page.")
    if len(moderators) > USERS_PER_PAGE:
        lines.append(f"Next page: /moderators {page + 1}")
    lines.extend(("", MODERATOR_COMMANDS))
    await message.reply("\n".join(lines), protect_content=True)


@router.message(F.text == "➕ Добавить пользователя")
async def add_user_prompt(message: types.Message):
    if await require_admin(message):
        await message.reply("Send /add_moderator ID to grant access to submissions.")


@router.message(F.text == "➖ Удалить пользователя")
async def remove_user_prompt(message: types.Message):
    if await require_admin(message):
        await message.reply("Send /remove_moderator ID to revoke a moderator’s access.")


@router.message(Command("add_moderator", "add_user"))
async def add_moderator(message: types.Message, command: CommandObject):
    if not await require_admin(message):
        return
    actor_id = message.from_user.id

    try:
        target = config.parse_user_id((command.args or "").strip())
    except ValueError:
        await message.reply("Use /add_moderator ID with a numeric Telegram ID.")
        return

    try:
        added = db.add_moderator(target, actor_id=actor_id)
    except db.PermissionDenied:
        await deny_access(message, db.get_user_role(actor_id))
        return

    if added:
        await message.reply(f"✅ Moderator {target} can now access submissions.", protect_content=True)
    else:
        await message.reply(f"User {target} already has access.", protect_content=True)


@router.message(Command("remove_moderator", "remove_user"))
async def remove_moderator(message: types.Message, command: CommandObject):
    if not await require_admin(message):
        return
    actor_id = message.from_user.id

    try:
        target = config.parse_user_id((command.args or "").strip())
    except ValueError:
        await message.reply("Use /remove_moderator ID with a numeric Telegram ID.")
        return

    try:
        removed = db.remove_moderator(target, actor_id=actor_id)
    except db.PermissionDenied:
        await deny_access(message, db.get_user_role(actor_id))
        return
    if removed:
        await message.reply(f"✅ Access revoked for moderator {target}.", protect_content=True)
    else:
        await message.reply("No moderator found with that Telegram ID.")


@router.error()
async def report_update_error(event: types.ErrorEvent) -> bool:
    logger.error("Error handling Telegram command (%s).", type(event.exception).__name__)
    return True


async def main():
    token = config.require_bot_token()
    config.require_web_app_url()
    db.init_db()

    # The polling and event loggers format raw exceptions from the transport.
    logging.getLogger("aiogram.dispatcher").setLevel(logging.CRITICAL + 1)
    logging.getLogger("aiogram.event").setLevel(logging.CRITICAL + 1)
    dispatcher = Dispatcher()
    dispatcher.include_router(router)
    async with Bot(token, session=AiohttpSession(timeout=10)) as bot:
        logger.info("Starting the Telegram bot.")
        await dispatcher.start_polling(
            bot,
            allowed_updates=dispatcher.resolve_used_update_types(),
            close_bot_session=False,
            tasks_concurrency_limit=8,
        )


def cli():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Telegram bot for managing submissions.")
    commands = parser.add_subparsers(dest="command")
    bootstrap = commands.add_parser("bootstrap-admin", help="Add the first administrator.")
    bootstrap.add_argument("user_id")
    args = parser.parse_args()

    if args.command == "bootstrap-admin":
        try:
            user_id = config.parse_user_id(args.user_id)
        except ValueError:
            parser.error("Enter the first administrator’s numeric Telegram ID.")
        db.init_db()
        if not db.bootstrap_admin(user_id):
            parser.exit(1, "An administrator already exists.\n")
        print("First administrator added.")
        return

    try:
        asyncio.run(main())
    except config.ConfigurationError as error:
        parser.exit(1, f"{error}\n")
    except AiogramError as error:
        logger.error("Telegram bot stopped (%s).", type(error).__name__)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        logger.info("Telegram bot stopped.")


if __name__ == "__main__":
    cli()
