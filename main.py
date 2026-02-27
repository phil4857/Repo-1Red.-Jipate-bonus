"""
Mkoba Wallet Backend
Fully aligned with HTML/JS frontend:
- User registration + OTP
- Login + verification
- Referral system
- Investments in commodities (OTP confirmed)
- 10% daily earnings
- Withdrawals (Monday only + OTP)
- Dashboard with earnings, bonus days, investment countdowns
"""

import time
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import bcrypt

# ---------------- APP SETUP ----------------

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

# ---------------- STORAGE ----------------

users: Dict[str, Dict[str, Any]] = {}
otps: Dict[str, Dict[str, Any]] = {}
pending_investments: Dict[str, Dict[str, Any]] = {}
pending_withdrawals: Dict[str, Dict[str, Any]] = {}
daily_bonus_claims: Dict[str, datetime] = {}

# ---------------- CONFIG ----------------

OTP_LENGTH = 6
OTP_TTL_SECONDS = 300

# ---------------- COMMODITIES ----------------

COMMODITY_INFO = {
    "marble": {"price": 650, "expiry_days": 15},
    "crude_oil": {"price": 800, "expiry_days": 20},
    "silver": {"price": 1000, "expiry_days": 23},
    "lead": {"price": 1200, "expiry_days": 25},
    "platinum": {"price": 1350, "expiry_days": 28},
    "diamonds": {"price": 1750, "expiry_days": 32},
    "gold": {"price": 2200, "expiry_days": 35},
    "uranium": {"price": 3000, "expiry_days": 45},
}

# ---------------- MODELS ----------------

class User(BaseModel):
    username: str
    phone: str
    password_hash: str
    approved: bool = False
    balance: float = 10000.0
    earnings: float = 0.0
    investments: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    referral: str = ""
    bonus_days_remaining: int = 0

# ---------------- HELPERS ----------------

def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def generate_otp() -> str:
    return ''.join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))

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

# ---------------- HEALTH ----------------

@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------- REGISTER ----------------

@app.post("/register")
def register(username: str = Form(...), phone: str = Form(...), password: str = Form(...), referral: str = Form("")):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=username,
        phone=phone,
        password_hash=hash_pwd(password),
        referral=referral
    )

    users[username] = user.dict()

    otp = generate_otp()
    store_otp(username, otp)

    logger.info(f"[OTP MOCK] Registration OTP for {username}: {otp}")

    return {"message": "User registered. OTP sent."}

# ---------------- VERIFY REGISTRATION ----------------

@app.post("/verify-otp")
def verify_registration(username: str = Form(...), otp: str = Form(...)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if verify_otp(username, otp):
        user["approved"] = True
        return {"message": "Account verified successfully"}

    raise HTTPException(status_code=400, detail="Invalid or expired OTP")

# ---------------- LOGIN ----------------

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
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
        "balance": user["balance"],
        "earnings": user["earnings"]
    }

# ---------------- DASHBOARD ----------------

@app.get("/dashboard")
def dashboard(username: str):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    investments_status = {}
    total_earnings = user["earnings"]

    for commodity, inv in user["investments"].items():
        start = inv["start_date"]
        expiry = inv["expiry_date"]

        remaining = expiry - datetime.utcnow()
        days_running = (datetime.utcnow() - start).days
        daily_profit = inv["amount"] * 0.10
        total_earned = daily_profit * max(days_running, 0)
        total_earnings += total_earned

        investments_status[commodity] = {
            "amount": inv["amount"],
            "daily_profit": daily_profit,
            "total_earned": total_earned,
            "expiry_date": expiry,
            "time_remaining": str(remaining).split(".")[0] if remaining.total_seconds() > 0 else "Expired"
        }

    return {
        "username": username,
        "balance": user["balance"],
        "earnings": total_earnings,
        "investments": investments_status,
        "bonus_days_remaining": user.get("bonus_days_remaining", 0)
    }

# ---------------- DAILY BONUS ----------------

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    last_claim = daily_bonus_claims.get(username)
    now = datetime.utcnow()
    if last_claim and (now - last_claim).total_seconds() < 24*3600:
        remaining = 24*3600 - (now - last_claim).total_seconds()
        raise HTTPException(status_code=400, detail=f"Bonus already claimed. Try again in {int(remaining//3600)}h {int((remaining%3600)//60)}m")

    bonus_amount = 500
    user["balance"] += bonus_amount
    daily_bonus_claims[username] = now
    user["bonus_days_remaining"] = user.get("bonus_days_remaining", 0) + 1

    return {"message": f"Daily bonus KES {bonus_amount} credited!"}

# ---------------- INVESTMENT ----------------

@app.post("/invest/request")
def invest_request(username: str = Form(...), commodity: str = Form(...)):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")
    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    price = COMMODITY_INFO[commodity]["price"]
    if user["balance"] < price:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    otp = generate_otp()
    store_otp(f"{username}_invest", otp)
    pending_investments[username] = {"commodity": commodity, "price": price}

    logger.info(f"[OTP MOCK] Investment OTP for {username}: {otp}")
    return {"message": "OTP sent to confirm investment"}

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
    user["investments"][commodity] = {
        "amount": price,
        "start_date": datetime.utcnow(),
        "expiry_date": datetime.utcnow() + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])
    }

    return {"message": f"Investment in {commodity} confirmed"}

# ---------------- WITHDRAWAL ----------------

@app.post("/withdraw/request")
def withdraw_request(username: str = Form(...), amount: float = Form(...)):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    if datetime.utcnow().weekday() != 0:  # Monday only
        raise HTTPException(status_code=400, detail="Withdrawals allowed only on Monday")

    if amount <= 0 or amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")

    otp = generate_otp()
    store_otp(f"{username}_withdraw", otp)
    pending_withdrawals[username] = {"amount": amount}

    logger.info(f"[OTP MOCK] Withdrawal OTP for {username}: {otp}")
    return {"message": "OTP sent to confirm withdrawal"}

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

    return {"message": f"Withdrawal of KES {amount} successful"}
