from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
import os
import time
import datetime
import sqlite3
import pytz
from token_manager import refresh_access_token, get_latest_token, scheduler as token_scheduler

# Load environment variables
load_dotenv()
API_KEYS = set(k.strip() for k in os.getenv("API_KEYS", "").split(","))

app = FastAPI()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# --- Models ---
class TokenResponse(BaseModel):
    access_token: str

class StatusResponse(BaseModel):
    access_token: str
    expiry: int
    expiry_readable: str
    now: int
    now_readable: str
    is_expired: bool
    expires_in_seconds: int
    issued_at: int
    issued_at_readable: str

# --- API Key Validation ---
def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

# --- Scheduler ---
scheduler = BackgroundScheduler()
token_scheduler = scheduler  # Share with token_manager
scheduler.start()

# --- API Endpoints ---
@app.get("/dgtoken", response_model=TokenResponse)
def get_token(api_key: str = Depends(verify_api_key)):
    token = get_latest_token()
    if not token:
        raise HTTPException(status_code=503, detail="Token not yet generated.")
    return {"access_token": token}

@app.post("/refresh")
def manual_refresh(api_key: str = Depends(verify_api_key)):
    refresh_access_token()
    return {"message": "Token refresh triggered"}

@app.get("/status", response_model=StatusResponse)
def get_status(api_key: str = Depends(verify_api_key)):
    tehran_tz = pytz.timezone("Asia/Tehran")
    with sqlite3.connect("tokens.db") as conn:
        row = conn.execute("SELECT access_token, expiry, timestamp FROM tokens ORDER BY timestamp DESC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No token found.")
        access_token, expiry, issued_at = row
        now = int(time.time())

        return {
            "access_token": access_token,
            "expiry": expiry,
            "expiry_readable": datetime.datetime.fromtimestamp(expiry, tehran_tz).isoformat(),
            "now": now,
            "now_readable": datetime.datetime.fromtimestamp(now, tehran_tz).isoformat(),
            "is_expired": now >= expiry,
            "expires_in_seconds": max(0, expiry - now),
            "issued_at": issued_at,
            "issued_at_readable": datetime.datetime.fromtimestamp(issued_at, tehran_tz).isoformat()
        }

@app.on_event("startup")
def startup_event():
    print("[INFO] Application starting up...")
    refresh_access_token()
