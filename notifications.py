import asyncio
import logging
import time

from aiogram import Bot
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.exceptions import (
    ClientDecodeError,
    TelegramAPIError,
    TelegramNetworkError,
    TelegramRetryAfter,
    TelegramServerError,
    TelegramUnauthorizedError,
)
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

import config
import db

logger = logging.getLogger(__name__)
IDLE_SECONDS = 2
PRUNE_INTERVAL_SECONDS = 3600


def retry_delivery(job: dict, delay: int, reason: str) -> None:
    outcome = "failed" if job["attempts"] >= db.MAX_NOTIFICATION_ATTEMPTS else "retry"
    db.finish_notification(job["id"], job["lease_token"], outcome=outcome, delay_seconds=delay)
    logger.warning("Notification %s: %s (%s).", job["id"], outcome, reason)


async def deliver_notification(bot: Bot, job: dict, web_app_url: str) -> int:
    try:
        chat_id = config.parse_user_id(str(job["chat_id"]))
    except ValueError:
        db.finish_notification(job["id"], job["lease_token"], outcome="failed")
        logger.warning("Notification %s: invalid recipient.", job["id"])
        return 0

    if not db.is_admin(chat_id) or db.get_form(job["form_id"]) is None:
        db.finish_notification(job["id"], job["lease_token"], outcome="failed")
        return 0

    try:
        await bot.send_message(
            chat_id=chat_id,
            text=f"New submission #{job['form_id']}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(
                    text="Open submissions",
                    web_app=WebAppInfo(url=web_app_url),
                ),
            ]]),
            protect_content=True,
        )
    except TelegramRetryAfter as error:
        delay = max(1, min(error.retry_after, 86_400))
        retry_delivery(job, delay, "Telegram rate limit")
        return min(delay, 30)
    except TelegramUnauthorizedError:
        retry_delivery(job, 60, "Telegram rejected the token")
        raise
    except (ClientDecodeError, TelegramNetworkError, TelegramServerError):
        retry_delivery(job, min(300, 10 * 2 ** (job["attempts"] - 1)), "temporary Telegram error")
    except TelegramAPIError as error:
        db.finish_notification(job["id"], job["lease_token"], outcome="failed")
        logger.warning("Notification %s: Telegram rejected delivery (%s).", job["id"], type(error).__name__)
    else:
        db.finish_notification(job["id"], job["lease_token"], outcome="sent")
    return 0


async def run_worker() -> None:
    token = config.require_bot_token()
    web_app_url = config.require_web_app_url()
    db.init_db()
    next_prune = 0.0
    async with Bot(token, session=AiohttpSession(timeout=10)) as bot:
        logger.info("Notification worker started.")
        while True:
            if time.monotonic() >= next_prune:
                db.prune_expired()
                next_prune = time.monotonic() + PRUNE_INTERVAL_SECONDS

            job = db.claim_notification()
            if job is None:
                await asyncio.sleep(IDLE_SECONDS)
                continue

            pause = await deliver_notification(bot, job, web_app_url)
            await asyncio.sleep(max(0.2, pause))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(run_worker())
    except config.ConfigurationError as error:
        logger.error("%s", error)
        raise SystemExit(1) from None
    except TelegramUnauthorizedError:
        logger.error("Notification worker stopped. Check BOT_TOKEN.")
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        logger.info("Notification worker stopped.")


if __name__ == "__main__":
    main()
