import logging
from datetime import datetime, timedelta
from typing import Dict, Any
import secrets
import string

from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt

# ---------------- APP SETUP ----------------
DATABASE_URL = "postgresql://mkobawallet_user:HjhGTY2y8VBADx52gGS2Eom3mngX41lt@dpg-d6jesmdm5p6s73dnkda0-a.singapore-postgres.render.com/mkobawallet"

app = FastAPI(title="Mkoba Wallet Backend")

origins = ["*"]  # Change to your Vercel domain in production for security

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
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    phone = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    approved = Column(Boolean, default=False)
    balance = Column(Float, default=0.0)
    earnings = Column(Float, default=0.0)
    investments = Column(JSON, default={})
    referral_code = Column(String, default="")  # username of referrer
    referral_bonus_earned = Column(Float, default=0.0)  # total bonus received from referrals

class WithdrawalRequest(Base):
    __tablename__ = "withdrawal_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String, default="pending")  # pending / approved / rejected
    requested_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

# ---------------- CONFIG ----------------
REFERRAL_BONUS_PERCENT = 10
MPESA_NUMBER = "0752964507"

# ---------------- HELPERS ----------------
def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

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

# ---------------- ROUTES ----------------
@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------- REGISTER ----------------
@app.post("/register")
def register(
    username: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    referral: str = Form(default="")
):
    db = SessionLocal()
    try:
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
            referral_code=referral if referral else None
        )

        db.add(new_user)
        db.commit()

        return {
            "message": f"User {username} registered successfully. Pending admin approval.",
            "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={username}"
        }
    finally:
        db.close()

# ---------------- LOGIN ----------------
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip().lower()).first()

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
    finally:
        db.close()

# ---------------- DASHBOARD ----------------
@app.get("/dashboard")
def dashboard(username: str = Query(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip().lower()).first()

        # Return defaults instead of 404 (prevents frontend error)
        if not user or not user.approved:
            return {
                "username": username,
                "balance": 0.0,
                "earnings": 0.0,
                "investments": {},
                "daily_earnings": 0.0,
                "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={username}",
                "referral_bonus_earned": 0.0,
                "approved": False
            }

        investments_status = {}
        daily_earnings = 0
        for commodity, inv in (user.investments or {}).items():
            expiry = datetime.fromisoformat(inv["expiry_date"])
            if datetime.utcnow() < expiry:
                daily_rate = inv["amount"] / COMMODITY_INFO[commodity]["expiry_days"]
                daily_earnings += daily_rate
                investments_status[commodity] = {
                    "amount": inv["amount"],
                    "days_remaining": max((expiry - datetime.utcnow()).days, 0),
                    "daily_earning": daily_rate
                }

        return {
            "username": user.username,
            "balance": user.balance,
            "earnings": user.earnings,
            "investments": investments_status,
            "daily_earnings": daily_earnings,
            "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={user.username}",
            "referral_bonus_earned": user.referral_bonus_earned,
            "approved": user.approved
        }
    finally:
        db.close()

# ---------------- INVESTMENT ----------------
@app.post("/invest/request")
def invest_request(username: str = Form(...), commodity: str = Form(...)):
    db = SessionLocal()
    try:
        username = username.strip().lower()
        user = db.query(UserDB).filter(UserDB.username == username).first()

        if not user or not user.approved:
            raise HTTPException(403, detail="Account not approved")
        if commodity not in COMMODITY_INFO:
            raise HTTPException(400, detail="Invalid commodity")

        price = COMMODITY_INFO[commodity]["price"]

        return {
            "message": "Investment request created",
            "price": price,
            "mpesa_number": MPESA_NUMBER
        }
    finally:
        db.close()

@app.post("/invest/confirm")
def invest_confirm(username: str = Form(...), commodity: str = Form(...)):
    db = SessionLocal()
    try:
        username = username.strip().lower()
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(404, detail="User not found")

        if commodity not in COMMODITY_INFO:
            raise HTTPException(400, detail="Invalid commodity")

        price = COMMODITY_INFO[commodity]["price"]

        investments = dict(user.investments or {})
        if commodity in investments:
            raise HTTPException(400, detail="Already invested in this commodity")

        investments[commodity] = {
            "amount": price,
            "start_date": datetime.utcnow().isoformat(),
            "expiry_date": (datetime.utcnow() + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])).isoformat()
        }
        user.investments = investments

        # Referral bonus: give 10% of this investment to referrer (only on first investment)
        if user.referral_code:
            referrer = db.query(UserDB).filter(UserDB.username == user.referral_code).first()
            if referrer:
                bonus = price * (REFERRAL_BONUS_PERCENT / 100)
                referrer.earnings += bonus
                referrer.referral_bonus_earned += bonus
                db.add(referrer)

        db.commit()

        return {"message": f"Investment in {commodity} confirmed"}

    finally:
        db.close()

# ---------------- WITHDRAWAL ----------------
@app.post("/withdraw/request")
def withdraw_request(username: str = Form(...), amount: float = Form(...)):
    db = SessionLocal()
    try:
        username = username.strip().lower()
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(404, detail="User not found")
        if amount < 500:
            raise HTTPException(400, detail="Minimum withdrawal KES 500")
        if user.balance < amount:
            raise HTTPException(400, detail="Insufficient balance")

        req = WithdrawalRequest(user_id=user.id, amount=amount)
        db.add(req)
        db.commit()

        logger.info(f"Withdrawal request: {username} for KES {amount}")

        return {"message": "Withdrawal request created. Awaiting admin approval."}
    finally:
        db.close()

# ---------------- ADMIN ----------------
ADMIN_PASSWORD = "PHIL4857"

@app.post("/admin/login")
def admin_login(password: str = Form(...)):
    if password != ADMIN_PASSWORD:
        raise HTTPException(403, detail="Invalid admin password")
    return {"message": "Admin login successful"}

@app.get("/admin/users")
def admin_list_users():
    db = SessionLocal()
    try:
        users = db.query(UserDB).all()
        return [
            {
                "username": u.username,
                "phone": u.phone,
                "approved": u.approved,
                "balance": u.balance,
                "earnings": u.earnings,
                "referral": u.referral_code,
                "referral_bonus_earned": u.referral_bonus_earned
            }
            for u in users
        ]
    finally:
        db.close()

@app.get("/admin/pending-withdrawals")
def admin_pending_withdrawals():
    db = SessionLocal()
    try:
        requests = db.query(WithdrawalRequest).filter(WithdrawalRequest.status == "pending").all()
        return [
            {
                "id": r.id,
                "username": db.query(UserDB).filter(UserDB.id == r.user_id).first().username,
                "amount": r.amount,
                "requested_at": r.requested_at
            }
            for r in requests
        ]
    finally:
        db.close()

@app.post("/admin/approve-user")
def admin_approve_user(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip().lower()).first()
        if not user:
            raise HTTPException(404, detail="User not found")
        user.approved = True
        db.commit()
        return {"message": f"User {username} approved"}
    finally:
        db.close()

@app.post("/admin/approve-withdrawal")
def admin_approve_withdrawal(request_id: int = Form(...)):
    db = SessionLocal()
    try:
        req = db.query(WithdrawalRequest).filter(WithdrawalRequest.id == request_id).first()
        if not req or req.status != "pending":
            raise HTTPException(400, detail="Invalid or already processed request")

        user = db.query(UserDB).filter(UserDB.id == req.user_id).first()
        if not user:
            raise HTTPException(404, detail="User not found")
        if user.balance < req.amount:
            raise HTTPException(400, detail="Insufficient balance")

        user.balance -= req.amount
        req.status = "approved"
        req.approved_at = datetime.utcnow()
        db.commit()

        return {"message": f"Withdrawal of KES {req.amount} approved for user {user.username}"}
    finally:
        db.close()

@app.post("/admin/terminate-user")
def admin_terminate_user(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip().lower()).first()
        if not user:
            raise HTTPException(404, detail="User not found")
        db.delete(user)
        db.commit()
        return {"message": f"User {username} terminated"}
    finally:
        db.close()

@app.post("/admin/reset-password")
def admin_reset_password(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip().lower()).first()
        if not user:
            raise HTTPException(404, detail="User not found")
        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        user.password_hash = hash_pwd(new_password)
        db.commit()
        return {"message": "Password reset successful", "new_password": new_password}
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
