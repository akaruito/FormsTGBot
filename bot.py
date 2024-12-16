import sqlite3
import logging
import asyncio
from aiogram import Bot, Dispatcher, types
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton, WebAppInfo
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram import Router, F

logging.basicConfig(level=logging.INFO)

API_TOKEN = 'Token'
ADMIN_ID = "AdminID"

bot = Bot(token=API_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
dp["bot"] = bot

conn = sqlite3.connect('forms.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    email_or_phone TEXT,
                    message TEXT,
                    timestamp TEXT,
                    viewed INTEGER DEFAULT 0)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE,
                    is_admin INTEGER DEFAULT 0)''')
conn.commit()

cursor.execute("INSERT OR IGNORE INTO users (user_id, is_admin) VALUES (?, 1)", (ADMIN_ID,))
conn.commit()

def is_authorized(user_id):
    cursor.execute("SELECT COUNT(*) FROM users WHERE user_id = ?", (str(user_id),))
    return cursor.fetchone()[0] > 0

def is_admin(user_id):
    cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (str(user_id),))
    result = cursor.fetchone()
    return result and result[0] == 1

router = Router()

@router.message(F.text == '/start')
async def start_command(message: types.Message):
    if not is_authorized(message.from_user.id):
        await message.reply("Access denied.")
        return

    buttons = []

    if is_admin(message.from_user.id):
        buttons.append([KeyboardButton(text="Добавить пользователя")])
        buttons.append([KeyboardButton(text="Удалить пользователя")])

    buttons.append([KeyboardButton(text="Меню форм", web_app=WebAppInfo(url="https://domain/miniapp.html"))])

    keyboard = ReplyKeyboardMarkup(keyboard=buttons, resize_keyboard=True)

    await message.reply("Выберите действие:", reply_markup=keyboard)

@router.message(F.text == 'Добавить пользователя')
async def add_user_prompt(message: types.Message):
    if not is_admin(message.from_user.id):
        await message.reply("Access denied.")
        return

    await message.reply("Введите команду в формате: /add_user <user_id>")

@router.message(F.text == 'Удалить пользователя')
async def remove_user_prompt(message: types.Message):
    if not is_admin(message.from_user.id):
        await message.reply("Access denied.")
        return

    await message.reply("Введите команду в формате: /remove_user <user_id>")

@router.message(F.text.startswith('/add_user'))
async def add_user(message: types.Message):
    if not is_admin(message.from_user.id):
        await message.reply("Access denied.")
        return

    args = message.text.split()
    if len(args) != 2:
        await message.reply("Usage: /add_user <user_id>")
        return

    new_user_id = args[1]
    try:
        cursor.execute("INSERT INTO users (user_id) VALUES (?)", (new_user_id,))
        conn.commit()
        await message.reply(f"User {new_user_id} added successfully.")
    except sqlite3.IntegrityError:
        await message.reply("User already exists.")

@router.message(F.text.startswith('/remove_user'))
async def remove_user(message: types.Message):
    if not is_admin(message.from_user.id):
        await message.reply("Access denied.")
        return

    args = message.text.split()
    if len(args) != 2:
        await message.reply("Usage: /remove_user <user_id>")
        return

    remove_user_id = args[1]
    cursor.execute("DELETE FROM users WHERE user_id = ?", (remove_user_id,))
    conn.commit()
    await message.reply(f"User {remove_user_id} removed successfully.")

dp.include_router(router)

async def main():
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())
