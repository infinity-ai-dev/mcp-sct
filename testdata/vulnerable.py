import sqlite3
import os
import subprocess

# SQL Injection - BAD
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# Command Injection - BAD
def ping_host(host):
    os.system(f"ping -c 1 {host}")

# Subprocess with shell=True - BAD
def run_command(cmd):
    subprocess.run(cmd, shell=True)

# Hardcoded secret - BAD
API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"

# Safe parameterized query - GOOD (should not trigger)
def get_user_safe(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
