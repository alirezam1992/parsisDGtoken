from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from apscheduler.schedulers.background import BackgroundScheduler
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import time
import datetime
import sqlite3
import pytz

from token_manager import (
    refresh_access_token,
    get_latest_token,
    get_next_refresh,
)

# --- Load .env ---
load_dotenv()
API_KEYS = set(k.strip() for k in os.getenv("API_KEYS", "").split(","))

# --- Security dependency ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

# --- FastAPI app ---
app = FastAPI()
scheduler = BackgroundScheduler()
scheduler.start()

# --- Models ---
class TokenResponse(BaseModel):
    access_token: str

class StatusResponse(BaseModel):
    access_token: str
    issued_at: str
    expiry: str
    now: str
    is_expired: bool
    expires_in_seconds: int
    next_refresh: str

# --- Startup logic ---
@app.on_event("startup")
def startup_event():
    print("[INFO] Starting scheduled token refresh every 55 minutes...")
    refresh_access_token()  # Immediate refresh
    scheduler.add_job(refresh_access_token, trigger='interval', minutes=55)

# --- Routes ---
@app.get("/dgtoken", response_model=TokenResponse)
def get_token(api_key: str = Depends(verify_api_key)):
    token = get_latest_token()
    if not token:
        raise HTTPException(status_code=404, detail="No token found.")
    return {"access_token": token}

@app.post("/refresh")
def manual_refresh(api_key: str = Depends(verify_api_key)):
    refresh_access_token()
    return {"status": "manual refresh triggered"}

@app.get("/status", response_model=StatusResponse)
def get_status(api_key: str = Depends(verify_api_key)):
    tehran_tz = pytz.timezone("Asia/Tehran")
    with sqlite3.connect("tokens.db") as conn:
        row = conn.execute("SELECT access_token, timestamp, expiry FROM tokens ORDER BY timestamp DESC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No token found.")
        access_token, issued_at, expiry = row
        now = int(time.time())

        return {
            "access_token": access_token,
            "issued_at": datetime.datetime.fromtimestamp(issued_at, tehran_tz).isoformat(),
            "expiry": datetime.datetime.fromtimestamp(expiry, tehran_tz).isoformat(),
            "now": datetime.datetime.fromtimestamp(now, tehran_tz).isoformat(),
            "is_expired": now >= expiry,
            "expires_in_seconds": max(0, expiry - now),
            "next_refresh": datetime.datetime.fromtimestamp(get_next_refresh(), tehran_tz).isoformat()
        }
