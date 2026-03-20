from flask import Flask, request
import os
import subprocess
import sqlite3

app = Flask(__name__)

# Taint flow: request.args -> variable -> SQL query (should detect)
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# Taint flow: request.form -> variable -> os.system (should detect)
@app.route("/ping")
def ping():
    host = request.form.get("host")
    cmd = "ping -c 1 " + host
    os.system(cmd)
    return "done"

# Taint flow: request.args -> variable -> open() (should detect)
@app.route("/file")
def read_file():
    filename = request.args.get("name")
    f = open("/data/" + filename, "r")
    return f.read()

# Safe: sanitized before use (should NOT detect)
@app.route("/safe")
def safe_user():
    user_id = request.args.get("id")
    safe_id = int(user_id)  # sanitizer: int()
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (safe_id,))
    return cursor.fetchone()
