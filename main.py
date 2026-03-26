import logging
from datetime import datetime, timedelta
from typing import Dict, Any
import secrets
import string
import os

from fastapi import FastAPI, Form, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, JSON, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import bcrypt

# ---------------- APP SETUP ----------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://mkobawallet_user:HjhGTY2y8VBADx52gGS2Eom3mngX41lt@dpg-d6jesmdm5p6s73dnkda0-a.singapore-postgres.render.com/mkobawallet"
)

app = FastAPI(title="Mkoba Wallet Backend")

origins = [
    "https://mkobawallets.vercel.app",
    "https://jipate-bonus-v1.vercel.app",
    "https://repo-1red-jipate-bonus-1.onrender.com",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")

# ---------------- DATABASE ----------------

Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    phone = Column(String, nullable=False)
    password_hash = Column(String(200), nullable=False)
    approved = Column(Boolean, default=False)
    balance = Column(Float, default=0.0)
    earnings = Column(Float, default=0.0)
    investments = Column(JSON, default=lambda: {})
    referral_code = Column(String, nullable=True)
    referral_bonus_earned = Column(Float, default=0.0)


class WithdrawalRequest(Base):
    __tablename__ = "withdrawal_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String, default="pending")
    requested_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)


Base.metadata.create_all(bind=engine)

# ---------------- CONFIG ----------------

REFERRAL_BONUS_PERCENT = 10
MPESA_NUMBER = "0752964507"

# Hardcoded admin password
ADMIN_PASSWORD = "PHIL4857"

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

# ---------------- HELPERS ----------------

def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_pwd(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


# ---------------- ROOT ----------------

@app.get("/")
async def root():
    return {"status": "online", "message": "Mkoba Wallet API running"}


@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------- REGISTER ----------------

@app.post("/register")
def register(
    username: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    referral: str = Form(default=""),
    db: Session = Depends(get_db)
):
    username = username.strip().lower()
    phone = phone.strip()
    referral = referral.strip().lower() if referral else None

    if db.query(UserDB).filter(UserDB.username == username).first():
        raise HTTPException(400, detail="Username already exists")

    hashed_pw = hash_pwd(password)

    new_user = UserDB(
        username=username,
        phone=phone,
        password_hash=hashed_pw,
        referral_code=referral
    )

    db.add(new_user)
    db.commit()

    return {
        "message": f"User {username} registered successfully. Awaiting admin approval.",
        "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={username}"
    }


# ---------------- LOGIN ----------------

@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    username = username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()

    if not user:
        raise HTTPException(404, detail="User not found")

    if not check_pwd(password, user.password_hash):
        raise HTTPException(400, detail="Invalid password")

    if not user.approved:
        raise HTTPException(403, detail="Account not approved")

    return {
        "message": "Login successful",
        "username": user.username,
        "balance": user.balance,
        "earnings": user.earnings,
        "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={user.username}",
        "referral_bonus_earned": user.referral_bonus_earned
    }


# ---------------- DASHBOARD ----------------

@app.get("/dashboard")
def dashboard(username: str = Query(...), db: Session = Depends(get_db)):
    username = username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()

    if not user or not user.approved:
        return {
            "username": username,
            "balance": 0.0,
            "earnings": 0.0,
            "investments": {},
            "daily_earnings": 0.0,
            "approved": False
        }

    investments = user.investments or {}
    now = datetime.utcnow()
    investments_status = {}
    daily_earnings = 0

    for commodity, inv in investments.items():
        expiry = datetime.fromisoformat(inv["expiry_date"])
        start = datetime.fromisoformat(inv["start_date"])

        if now >= expiry:
            continue

        days = COMMODITY_INFO[commodity]["expiry_days"]
        daily_rate = inv["amount"] / days

        last_credited = datetime.fromisoformat(inv.get("last_credited", start.isoformat()))
        days_to_credit = (now - last_credited).days

        if days_to_credit > 0:
            credit = daily_rate * days_to_credit
            user.balance += credit
            user.earnings += credit
            inv["last_credited"] = now.isoformat()

        investments_status[commodity] = {
            "amount": inv["amount"],
            "days_remaining": max((expiry - now).days, 0),
            "daily_earning": daily_rate
        }

        daily_earnings += daily_rate

    user.investments = investments
    db.commit()

    return {
        "username": user.username,
        "balance": user.balance,
        "earnings": user.earnings,
        "investments": investments_status,
        "daily_earnings": daily_earnings,
        "approved": user.approved,
        "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={user.username}",
        "referral_bonus_earned": user.referral_bonus_earned
    }


# ---------------- INVESTMENT ----------------

@app.post("/invest/request")
def invest_request(username: str = Form(...), commodity: str = Form(...)):
    if commodity not in COMMODITY_INFO:
        raise HTTPException(400, detail="Invalid commodity")

    price = COMMODITY_INFO[commodity]["price"]

    return {
        "message": "Send payment to M-Pesa",
        "price": price,
        "mpesa_number": MPESA_NUMBER
    }


@app.post("/invest/confirm")
def invest_confirm(
    username: str = Form(...),
    commodity: str = Form(...),
    db: Session = Depends(get_db)
):
    username = username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()

    if not user:
        raise HTTPException(404, detail="User not found")

    if commodity not in COMMODITY_INFO:
        raise HTTPException(400, detail="Invalid commodity")

    price = COMMODITY_INFO[commodity]["price"]
    investments = dict(user.investments or {})

    if commodity in investments:
        raise HTTPException(400, detail="Already invested")

    now = datetime.utcnow()
    investments[commodity] = {
        "amount": price,
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])).isoformat(),
        "last_credited": now.isoformat()
    }

    user.investments = investments

    if user.referral_code:
        referrer = db.query(UserDB).filter(UserDB.username == user.referral_code).first()
        if referrer:
            bonus = price * (REFERRAL_BONUS_PERCENT / 100)
            referrer.earnings += bonus
            referrer.referral_bonus_earned += bonus

    db.commit()
    return {"message": f"Investment in {commodity} confirmed"}


# ---------------- WITHDRAW ----------------

@app.post("/withdraw/request")
def withdraw_request(
    username: str = Form(...),
    amount: float = Form(...),
    db: Session = Depends(get_db)
):
    username = username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()

    if not user:
        raise HTTPException(404, detail="User not found")

    if amount < 500:
        raise HTTPException(400, detail="Minimum withdrawal is KES 500")

    if user.balance < amount:
        raise HTTPException(400, detail="Insufficient balance")

    req = WithdrawalRequest(user_id=user.id, amount=amount)
    db.add(req)
    db.commit()

    logger.info(f"Withdrawal requested: {username} KES {amount}")

    return {"message": "Withdrawal request submitted"}
