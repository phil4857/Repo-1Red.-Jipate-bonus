by# main.py
"""
Mkoba Wallet Backend
- User registration + OTP
- Commodity trading: Silver, Gold, Marble, Diamond, Uranium
- Investment + OTP confirmation
- Withdrawal (Monday only + OTP verification)
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

# Optional: load .env in development
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ---- App ----
app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Logging ----
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")

# ---- In-memory stores ----
users: Dict[str, Dict[str, Any]] = {}
otps: Dict[str, Dict[str, Any]] = {}
pending_investments: Dict[str, Dict[str, Any]] = {}
pending_withdrawals: Dict[str, Dict[str, Any]] = {}

# ---- Config ----
PLATFORM_NAME = os.getenv("PLATFORM_NAME", "Mkoba Wallet")
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))

# ---- Commodity Prices and Expiry ----
COMMODITY_INFO = {
    "silver": {"price": 550, "expiry_days": 10},
    "marble": {"price": 650, "expiry_days": 13},
    "uranium": {"price": 1250, "expiry_days": 20},
    "diamond": {"price": 1850, "expiry_days": 30},
    "gold": {"price": 2050, "expiry_days": 40},
}

# ---- Models ----
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    balance: float = 0.0
    investments: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

# ---- Helpers ----
def hash_pwd(pw: str) -> str:
    import bcrypt
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def generate_otp(length: int = OTP_LENGTH) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))

def store_otp(key: str, otp: str):
    otps[key] = {
        "otp": otp,
        "expires_at": time.time() + OTP_TTL_SECONDS
    }

def verify_otp(key: str, otp: str) -> bool:
    rec = otps.get(key)
    if not rec:
        return False
    if time.time() > rec["expires_at"]:
        otps.pop(key, None)
        return False
    if rec["otp"] == otp:
        otps.pop(key, None)
        return True
    return False

# ---- Public Endpoints ----
@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time()}

@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...)
):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    pwd_hash = hash_pwd(password)

    users[username] = User(
        username=username,
        number=number,
        password_hash=pwd_hash
    ).dict()

    otp = generate_otp()
    store_otp(username, otp)

    logger.info(f"[SMS MOCK] To: {number} | OTP: {otp}")

    return {"message": "User registered. OTP sent."}

@app.post("/verify-otp")
def verify_registration_otp(username: str = Form(...), otp: str = Form(...)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if verify_otp(username, otp):
        user["approved"] = True
        return {"message": "Account verified and approved"}

    raise HTTPException(status_code=400, detail="Invalid or expired OTP")

# ---- Investment Flow ----
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

    logger.info(f"[SMS MOCK] To: {user['number']} | Investment OTP: {otp}")

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

    expiry_date = datetime.utcnow() + timedelta(
        days=COMMODITY_INFO[commodity]["expiry_days"]
    )

    user["investments"].setdefault(commodity, {
        "amount": 0,
        "expiry_date": expiry_date
    })

    user["investments"][commodity]["amount"] += price
    user["investments"][commodity]["expiry_date"] = expiry_date

    return {"message": f"Investment in {commodity} confirmed"}

# ---- Withdrawal Flow ----
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

    logger.info(f"[SMS MOCK] To: {user['number']} | Withdrawal OTP: {otp}")

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

    return {"message": f"Withdrawal of {amount} successful"}

# ---- Dashboard ----
@app.get("/dashboard")
def dashboard(username: str):
    user = users.get(username)
    if not user or not user.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    investment_status = {}

    for commodity, inv in user["investments"].items():
        expiry: datetime = inv["expiry_date"]
        now = datetime.utcnow()
        remaining = expiry - now
        if remaining.total_seconds() < 0:
            remaining = timedelta(0)
        investment_status[commodity] = {
            "amount": inv["amount"],
            "expiry_date": expiry.isoformat(),
            "time_remaining": str(remaining),
            "hours_remaining": int(remaining.total_seconds() // 3600)
        }

    return {
        "username": username,
        "balance": user["balance"],
        "active_investments": [
            {
                "commodity": c,
                "amount": v["amount"],
                "start_date": (datetime.utcnow() - timedelta(days=0)).isoformat(),  # placeholder
                "duration_days": COMMODITY_INFO[c]["expiry_days"]
            }
            for c, v in user["investments"].items()
        ]
    }
