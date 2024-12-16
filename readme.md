# Forms Telegram Bot

Telegram bot and server for receiving forms from the site and viewing them in the telegram bot via MiniApp

Currently supported languages: Russian

Functions: view form, mark (viewed/unviewed), delete

Tested on: Ubuntu 24.04
## How to Install

1. Installing Dependencies and Applications:
   ```bash
   sudo apt update
   sudo apt install python3 python3-venv python3-pip sqlite3 git
   ```
2. Installing Nginx
   ```bash
   sudo apt install nginx -y
   ```
3. Clone the repository
   ```bash
   git clone https://github.com/akaruito/FormsTGBot.git
   cd FormsTGBot
4. Create a virtual environment:
   ```bash
   python3 -m venv venv
5. Activate the virtual environment:
   ```bash
   source venv/bin/activate
6. Install dependencies:
   ```bash
   pip install -r requirements.txt
7. Setting up SQLite
   ```bash
   sqlite3 forms.db
   ```
7.1 Within SQLite, run the following commands to create tables
   ```bash
   CREATE TABLE IF NOT EXISTS forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email_or_phone TEXT,
    message TEXT,
    timestamp TEXT,
    viewed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE,
    is_admin INTEGER DEFAULT 0
);
   ```
   ```bash
INSERT INTO users (user_id, is_admin) VALUES ('YOUR_ADMIN_USER_ID', 1);
   ```
8. Change token, admin id in bot.py and secret in server.py
9. Change form action in html file
10. Setup nginx via site-conf file provided
11. Run Flask server:
   ```bash
   python3 server.py
   ```
12. Run Telegram bot(separate window, only in venv):
   ```bash
   python3 bot.py
   ```
