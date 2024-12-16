from flask import Flask, request, jsonify, render_template, redirect, url_for
import sqlite3
from datetime import datetime
import uuid
import logging

app = Flask(__name__)
app.secret_key = ''

logging.basicConfig(level=logging.INFO)

def connect_db():
    conn = sqlite3.connect('forms.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT,
            email TEXT,
            message TEXT,
            timestamp TEXT,
            form_id TEXT,
            viewed INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    return conn

def update_table_structure():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(forms)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'phone' not in columns:
        cursor.execute("ALTER TABLE forms ADD COLUMN phone TEXT")
    if 'email' not in columns:
        cursor.execute("ALTER TABLE forms ADD COLUMN email TEXT")
    if 'form_id' not in columns:
        cursor.execute("ALTER TABLE forms ADD COLUMN form_id TEXT")
    
    conn.commit()
    conn.close()

update_table_structure()

@app.route('/')
def index():
    form_id = str(uuid.uuid4())
    logging.info(f"Generated form ID: {form_id}")
    return render_template('index.html', form_id=form_id)

@app.route('/submit-form', methods=['POST'])
def submit_form():
    form_id = request.form.get('form_id')
    
    logging.info(f"Form ID: {form_id}")

    data = request.form
    name = data.get('name')
    phone = data.get('phone')
    email = data.get('email')
    message = data.get('message')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not (name and phone and email and message and form_id):
        logging.error("All fields are required.")
        return jsonify({"error": "All fields are required."}), 400

    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO forms (name, phone, email, message, timestamp, form_id) VALUES (?, ?, ?, ?, ?, ?)",
            (name, phone, email, message, timestamp, form_id),
        )
        conn.commit()
        conn.close()
        logging.info(f"Form submitted successfully: {data}")
    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({"error": "Database error."}), 500

    return redirect(url_for('success'))

@app.route('/success')
def success():
    return render_template('sendsuccess.html')

@app.route('/get-forms', methods=['GET'])
def get_forms():
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, phone, email, message, timestamp, viewed FROM forms")
        forms = cursor.fetchall()
        conn.close()
        
        forms_list = [{"id": form[0], "name": form[1], "phone": form[2], "email": form[3], "message": form[4], "timestamp": form[5], "viewed": form[6]} for form in forms]
        logging.info(f"Forms retrieved successfully: {forms_list}")
        return jsonify(forms_list)
    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({"error": "Database error."}), 500

@app.route('/get-form/<int:id>', methods=['GET'])
def get_form(id):
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, phone, email, message, timestamp, viewed FROM forms WHERE id = ?", (id,))
        form = cursor.fetchone()
        conn.close()
        
        if form:
            form_data = {"id": form[0], "name": form[1], "phone": form[2], "email": form[3], "message": form[4], "timestamp": form[5], "viewed": form[6]}
            logging.info(f"Form retrieved successfully: {form_data}")
            return jsonify(form_data)
        else:
            logging.error("Form not found.")
            return jsonify({"error": "Form not found"}), 404
    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({"error": "Database error."}), 500

@app.route('/toggle-viewed/<int:id>', methods=['POST'])
def toggle_viewed(id):
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE forms SET viewed = NOT viewed WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        logging.info(f"Form viewed status toggled for form ID: {id}")
        return jsonify({"success": "Form viewed status toggled!"})
    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({"error": "Database error."}), 500

@app.route('/delete-form/<int:id>', methods=['POST'])
def delete_form(id):
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM forms WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        logging.info(f"Form deleted successfully: ID {id}")
        return jsonify({"success": "Form deleted successfully!"})
    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({"error": "Database error."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
