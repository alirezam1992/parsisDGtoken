from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
import os
import time
from token_manager import refresh_access_token, get_latest_token, scheduler as token_scheduler

# Load environment variables
load_dotenv()
EXPECTED_API_KEY = os.getenv("API_KEY", "").strip()

app = FastAPI()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# --- Models ---
class TokenResponse(BaseModel):
    access_token: str

# --- API Key Validation ---
def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != EXPECTED_API_KEY:
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

@app.on_event("startup")
def startup_event():
    print("[INFO] Application starting up...")
    refresh_access_token()
