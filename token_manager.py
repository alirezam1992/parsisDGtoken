import sqlite3
import requests
import time
import os
import jwt
import datetime
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()
refresh_token = os.getenv("REFRESH_TOKEN", "").strip()

if not refresh_token:
    print("[ERROR] REFRESH_TOKEN is missing or empty in .env")

db_path = "tokens.db"
token_api_url = "https://seller.digikala.com/open-api/v1/auth/refresh-token"
next_refresh_timestamp = 0  # global to track refresh schedule

# --- Init database ---
def init_db():
    with sqlite3.connect(db_path) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_token TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            expiry INTEGER NOT NULL
        )''')

init_db()

# --- Save new token ---
def save_token(token: str):
    global next_refresh_timestamp
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        expiry = payload.get("exp", 0)
    except Exception as e:
        print(f"[WARN] Could not decode token expiry: {e}")
        expiry = 0

    issued_at = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO tokens (access_token, timestamp, expiry) VALUES (?, ?, ?)",
            (token, issued_at, expiry)
        )

    # calculate next refresh time (55 minutes later)
    next_refresh_timestamp = issued_at + (55 * 60)
    return expiry

# --- Get latest token ---
def get_latest_token():
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT access_token FROM tokens ORDER BY timestamp DESC LIMIT 1").fetchone()
        return row[0] if row else ""

# --- Get next refresh time ---
def get_next_refresh():
    global next_refresh_timestamp
    return next_refresh_timestamp

# --- Refresh token ---
def refresh_access_token():
    current_token = get_latest_token() or os.getenv("ACCESS_TOKEN", "").strip()
    headers = {"Content-Type": "application/json"}
    payload = {
        "access_token": current_token,
        "refresh_token": refresh_token
    }
    try:
        print(f"[DEBUG] Using access_token: {current_token[:10]}..., refresh_token: {refresh_token[:10]}...")
        response = requests.post(token_api_url, json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]
            access_token = data["access_token"]
            expiry = save_token(access_token)
            print(f"[INFO] Token refreshed: {access_token[:30]}... (exp: {expiry})")
        else:
            print(f"[ERROR] Failed to refresh token [{response.status_code}]: {response.text}")
    except Exception as e:
        print(f"[EXCEPTION] {e}")
