import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import bcrypt

# ==========================================================
# APP SETUP
# ==========================================================

app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # CHANGE in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")

# ==========================================================
# CONFIG
# ==========================================================

ADMIN_SECRET = "admin123"  # CHANGE THIS
REFERRAL_PERCENT = 0.10

# ==========================================================
# DEMO STORAGE (NOT FOR PRODUCTION)
# ==========================================================

users: Dict[str, Dict[str, Any]] = {}

# ==========================================================
# COMMODITIES
# ==========================================================

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

# ==========================================================
# MODELS
# ==========================================================

class User(BaseModel):
    username: str
    phone: str
    password_hash: str
    approved: bool = False

    balance: float = 10000.0
    earnings: float = 0.0
    investments: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    referral_code: str = ""
    referred_by: str = ""
    referral_earnings: float = 0.0


# ==========================================================
# HELPERS
# ==========================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_referral_code() -> str:
    return secrets.token_hex(4)


def find_user_by_referral_code(code: str):
    for user in users.values():
        if user["referral_code"] == code:
            return user
    return None


# ==========================================================
# HEALTH
# ==========================================================

@app.get("/health")
def health():
    return {"status": "ok"}


# ==========================================================
# REGISTER
# ==========================================================

@app.post("/register")
def register(
    username: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    referral: str = Form("")
):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    referral_code = generate_referral_code()

    new_user = User(
        username=username,
        phone=phone,
        password_hash=hash_password(password),
        referral_code=referral_code,
        referred_by=referral
    )

    users[username] = new_user.dict()

    return {
        "message": "Registration successful. Await admin approval.",
        "referral_link": f"https://yourfrontend.com/register?ref={referral_code}"
    }


# ==========================================================
# ADMIN APPROVAL
# ==========================================================

@app.post("/admin/approve")
def approve_user(username: str = Form(...), admin_key: str = Form(...)):
    if admin_key != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user["approved"] = True

    return {"message": f"{username} approved successfully"}


@app.get("/admin/users")
def list_users(admin_key: str):
    if admin_key != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

    return users


# ==========================================================
# LOGIN
# ==========================================================

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid password")

    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")

    return {
        "message": "Login successful",
        "username": username,
        "balance": user["balance"],
        "earnings": user["earnings"]
    }


# ==========================================================
# DASHBOARD
# ==========================================================

@app.get("/dashboard")
def dashboard(username: str):
    user = users.get(username)

    if not user or not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")

    investment_data = {}

    for commodity, inv in user["investments"].items():
        remaining_days = max(
            (inv["expiry_date"] - datetime.utcnow()).days, 0
        )
        investment_data[commodity] = {
            "amount": inv["amount"],
            "days_remaining": remaining_days
        }

    return {
        "username": username,
        "balance": user["balance"],
        "earnings": user["earnings"],
        "investments": investment_data
    }


# ==========================================================
# INVEST
# ==========================================================

@app.post("/invest")
def invest(username: str = Form(...), commodity: str = Form(...)):
    user = users.get(username)

    if not user or not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")

    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    price = COMMODITY_INFO[commodity]["price"]

    if user["balance"] < price:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # Deduct balance
    user["balance"] -= price

    # Add investment
    user["investments"][commodity] = {
        "amount": price,
        "start_date": datetime.utcnow(),
        "expiry_date": datetime.utcnow() + timedelta(
            days=COMMODITY_INFO[commodity]["expiry_days"]
        )
    }

    # ---------- REFERRAL BONUS ----------
    if user["referred_by"]:
        referrer = find_user_by_referral_code(user["referred_by"])
        if referrer:
            bonus = price * REFERRAL_PERCENT
            referrer["balance"] += bonus
            referrer["referral_earnings"] += bonus
    # ------------------------------------

    return {"message": f"Investment in {commodity} successful"}


# ==========================================================
# WITHDRAW
# ==========================================================

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    user = users.get(username)

    if not user or not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")

    if datetime.utcnow().weekday() != 0:
        raise HTTPException(
            status_code=400,
            detail="Withdrawals allowed only on Monday"
        )

    if amount <= 0 or amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Invalid amount")

    user["balance"] -= amount

    return {"message": f"Withdrawal of KES {amount} successful"}


# ==========================================================
# REFERRAL INFO
# ==========================================================

@app.get("/referral-info")
def referral_info(username: str):
    user = users.get(username)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "referral_code": user["referral_code"],
        "referral_link": f"https://yourfrontend.com/register?ref={user['referral_code']}",
        "referral_earnings": user["referral_earnings"]
    }
