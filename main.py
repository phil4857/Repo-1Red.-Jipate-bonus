"""
Mkoba Wallet Backend
Features:
- User Registration + OTP verification
- Login
- Commodity Investments (OTP confirmed)
- Withdrawals (Monday only + OTP)
- Dashboard with countdown timers
"""

import os
import time
import secrets
import logging
from typing import Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Optional .env loading
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ---- App Setup ----
app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")

# ---- In-memory storage ----
users: Dict[str, Dict[str, Any]] = {}
otps: Dict[str, Dict[str, Any]] = {}
pending_investments: Dict[str, Dict[str, Any]] = {}
pending_withdrawals: Dict[str, Dict[str, Any]] = {}

# ---- Config ----
OTP_LENGTH = 6
OTP_TTL_SECONDS = 300

# ---- Commodity Info ----
COMMODITY_INFO = {
    "marble": {"price": 650, "expiry_days": 15},
    "crude_oil": {"price": 800, "expiry_days": 20},
    "silver": {"price": 1000, "expiry_days": 23},
    "lead": {"price": 1200, "expiry_days": 25},
    "platinum": {"price": 1350, "expiry_days": 28},
    "diamonds": {"price": 1750, "expiry_days": 32},
    "gold": {"price": 2200, "expiry_days": 35},
    "uranium": {"price": 3000, "expiry_days": 45}
}

# ---- Models ----
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    balance: float = 10000.0   # starter balance for testing
    investments: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

# ---- Helpers ----
def hash_pwd(pw: str) -> str:
    import bcrypt
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def generate_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))

def store_otp(key: str, otp: str):
    otps[key] = {
        "otp": otp,
        "expires_at": time.time() + OTP_TTL_SECONDS
    }

def verify_otp(key: str, otp: str) -> bool:
    record = otps.get(key)
    if not record:
        return False
    if time.time() > record["expires_at"]:
        otps.pop(key, None)
        return False
    if record["otp"] == otp:
        otps.pop(key, None)
        return True
    return False

# ---- Health ----
@app.get("/health")
def health():
    return {"status": "ok"}

# ---- Registration ----
@app.post("/register")
async def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...)
):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=username,
        number=number,
        password_hash=hash_pwd(password)
    )

    users[username] = user.dict()

    otp = generate_otp()
    store_otp(username, otp)

    logger.info(f"[OTP MOCK] Registration OTP for {username}: {otp}")

    return {"message": "User registered. OTP sent."}

# ---- Verify Registration OTP ----
@app.post("/verify-otp")
def verify_registration(username: str = Form(...), otp: str = Form(...)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if verify_otp(username, otp):
        user["approved"] = True
        return {"message": "Account verified successfully"}

    raise HTTPException(status_code=400, detail="Invalid or expired OTP")

# ---- Login ----
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not check_pwd(password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid password")

    if not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not verified")

    return {
        "message": "Login successful",
        "username": username,
        "balance": user["balance"]
    }

# ---- Investment Request ----
@app.post("/invest/request")
def invest_request(username: str = Form(...), commodity: str = Form(...)):
    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    price = COMMODITY_INFO[commodity]["price"]

    if user["balance"] < price:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    otp = generate_otp()
    store_otp(f"{username}_invest", otp)

    pending_investments[username] = {
        "commodity": commodity,
        "price": price
    }

    logger.info(f"[OTP MOCK] Investment OTP for {username}: {otp}")

    return {"message": "OTP sent to confirm investment"}

# ---- Confirm Investment ----
@app.post("/invest/confirm")
def invest_confirm(username: str = Form(...), otp: str = Form(...)):
    if not verify_otp(f"{username}_invest", otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    pending = pending_investments.pop(username, None)
    if not pending:
        raise HTTPException(status_code=400, detail="No pending investment")

    user = users[username]
    commodity = pending["commodity"]
    price = pending["price"]

    user["balance"] -= price

    expiry_date = datetime.utcnow() + timedelta(
        days=COMMODITY_INFO[commodity]["expiry_days"]
    )

    user["investments"][commodity] = {
        "amount": price,
        "expiry_date": expiry_date
    }

    return {"message": f"Investment in {commodity} confirmed"}

# ---- Withdrawal Request ----
@app.post("/withdraw/request")
def withdraw_request(username: str = Form(...), amount: float = Form(...)):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    if datetime.utcnow().weekday() != 0:
        raise HTTPException(status_code=400, detail="Withdrawals allowed only on Monday")

    if amount <= 0 or amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")

    otp = generate_otp()
    store_otp(f"{username}_withdraw", otp)

    pending_withdrawals[username] = {"amount": amount}

    logger.info(f"[OTP MOCK] Withdrawal OTP for {username}: {otp}")

    return {"message": "OTP sent to confirm withdrawal"}

# ---- Confirm Withdrawal ----
@app.post("/withdraw/confirm")
def withdraw_confirm(username: str = Form(...), otp: str = Form(...)):
    if not verify_otp(f"{username}_withdraw", otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    pending = pending_withdrawals.pop(username, None)
    if not pending:
        raise HTTPException(status_code=400, detail="No pending withdrawal")

    user = users[username]
    amount = pending["amount"]

    user["balance"] -= amount

    return {"message": f"Withdrawal of {amount} successful"}

# ---- Dashboard ----
@app.get("/dashboard")
def dashboard(username: str):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    investment_status = {}

    for commodity, inv in user["investments"].items():
        expiry = inv["expiry_date"]
        remaining = expiry - datetime.utcnow()
        hours_remaining = int(remaining.total_seconds() // 3600)

        investment_status[commodity] = {
            "amount": inv["amount"],
            "expiry_date": expiry,
            "time_remaining": str(remaining).split(".")[0],
            "hours_remaining": hours_remaining
        }

    return {
        "username": username,
        "balance": user["balance"],
        "investments": investment_status
    }
