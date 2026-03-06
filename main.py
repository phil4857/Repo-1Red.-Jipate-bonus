import logging
from datetime import datetime, timedelta
from typing import Dict, Any
import secrets
import string

from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt

# ---------------- APP SETUP ----------------
DATABASE_URL = "postgresql://mkobawallet_user:HjhGTY2y8VBADx52gGS2Eom3mngX41lt@dpg-d6jesmdm5p6s73dnkda0-a.singapore-postgres.render.com/mkobawallet"

app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ← Change to your Vercel domain in production, e.g. ["https://your-app.vercel.app"]
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
    referral = Column(String, default="")
    bonus_days_remaining = Column(Integer, default=0)


Base.metadata.create_all(bind=engine)

# ---------------- HELPERS ----------------
def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_pwd(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


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

MPESA_NUMBER = "0752964507"

REFERRAL_BONUS_PERCENT = 10
PENDING_INVESTMENTS: Dict[str, Dict[str, Any]] = {}
PENDING_WITHDRAWALS: Dict[str, Dict[str, Any]] = {}

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
        username = username.strip()
        phone = phone.strip()
        referral = referral.strip()

        if not username or not phone or not password:
            raise HTTPException(status_code=400, detail="All fields are required")

        if db.query(UserDB).filter(UserDB.username == username).first():
            raise HTTPException(status_code=400, detail="Username already exists")

        hashed_pw = hash_pwd(password)
        new_user = UserDB(username=username, phone=phone, password_hash=hashed_pw, referral=referral)
        db.add(new_user)

        if referral:
            ref_user = db.query(UserDB).filter(UserDB.username == referral).first()
            if ref_user:
                bonus = new_user.balance * (REFERRAL_BONUS_PERCENT / 100)  # usually 0
                ref_user.balance += bonus
                logger.info(f"Referral bonus: {bonus} added to {ref_user.username}")

        db.commit()
        db.refresh(new_user)
        logger.info(f"User {username} registered successfully")
        return {"message": f"User {username} registered successfully. Pending admin approval."}
    except HTTPException as e:
        db.rollback()
        raise e
    except Exception as e:
        db.rollback()
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Server error during registration")
    finally:
        db.close()

# ---------------- LOGIN ----------------
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not check_pwd(password, user.password_hash):
            raise HTTPException(status_code=400, detail="Invalid password")
        if not user.approved:
            raise HTTPException(status_code=403, detail="Account not approved")
        return {"message": "Login successful", "username": username, "balance": user.balance, "earnings": user.earnings}
    finally:
        db.close()

# ---------------- DASHBOARD ----------------
@app.get("/dashboard")
def dashboard(username: str = Query(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not user.approved:
            raise HTTPException(status_code=403, detail="Account not approved. Contact admin to get approved.")

        investments_status = {}
        daily_earnings = 0.0
        for commodity, inv in (user.investments or {}).items():
            try:
                expiry = datetime.fromisoformat(inv["expiry_date"])
                if datetime.utcnow() < expiry:
                    daily_rate = inv["amount"] / COMMODITY_INFO[commodity]["expiry_days"]
                    daily_earnings += daily_rate
                    investments_status[commodity] = {
                        "amount": inv["amount"],
                        "days_remaining": max((expiry - datetime.utcnow()).days, 0),
                        "daily_earning": daily_rate
                    }
            except (KeyError, ValueError):
                continue  # skip invalid investment entries

        return {
            "username": username,
            "balance": user.balance,
            "earnings": user.earnings,
            "investments": investments_status,
            "daily_earnings": daily_earnings
        }
    finally:
        db.close()

# ---------------- INVESTMENT ----------------
@app.post("/invest/request")
def invest_request(username: str = Form(...), commodity: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        if not user or not user.approved:
            raise HTTPException(status_code=403, detail="Account not approved")

        if commodity not in COMMODITY_INFO:
            raise HTTPException(status_code=400, detail="Invalid commodity")

        # In real app you might store pending request here
        # For now just return payment instruction
        return {
            "message": f"Investment request for {commodity} created. Pending confirmation.",
            "mpesa_payment": f"Send KES {COMMODITY_INFO[commodity]['price']} to M-Pesa: {MPESA_NUMBER}"
        }
    finally:
        db.close()

@app.post("/invest/confirm")
def invest_confirm(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        pending = PENDING_INVESTMENTS.pop(username.strip(), None)
        if not user or not user.approved or not pending:
            raise HTTPException(status_code=400, detail="No pending investment or user not approved")
        
        price = pending["price"]
        commodity = pending["commodity"]
        
        if user.balance < price:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        user.balance -= price
        investments = user.investments or {}
        investments[commodity] = {
            "amount": price,
            "start_date": datetime.utcnow().isoformat(),
            "expiry_date": (datetime.utcnow() + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])).isoformat()
        }
        user.investments = investments
        db.commit()
        db.refresh(user)
        return {"message": f"Investment in {commodity} confirmed"}
    finally:
        db.close()

# ---------------- WITHDRAWAL ----------------
@app.post("/withdraw/request")
def withdraw_request(username: str = Form(...), amount: float = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        if not user or not user.approved:
            raise HTTPException(status_code=403, detail="Account not approved")

        daily_earnings = 0.0
        for commodity, inv in (user.investments or {}).items():
            try:
                expiry = datetime.fromisoformat(inv["expiry_date"])
                if datetime.utcnow() < expiry:
                    daily_rate = inv["amount"] / COMMODITY_INFO[commodity]["expiry_days"]
                    daily_earnings += daily_rate
            except:
                continue

        if amount <= 0 or amount > daily_earnings:
            raise HTTPException(status_code=400, detail=f"Withdrawal amount must be between 0 and your current daily earnings (KES {daily_earnings:.2f})")

        PENDING_WITHDRAWALS[username.strip()] = {"amount": amount}
        return {"message": f"Withdrawal request for KES {amount} created. Pending admin approval."}
    finally:
        db.close()

@app.post("/withdraw/confirm")
def withdraw_confirm(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        pending = PENDING_WITHDRAWALS.pop(username.strip(), None)
        if not user or not user.approved or not pending:
            raise HTTPException(status_code=400, detail="No pending withdrawal or user not approved")
        amount = pending["amount"]
        if user.balance < amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        user.balance -= amount
        db.commit()
        db.refresh(user)
        return {"message": f"Withdrawal of KES {amount} successful"}
    finally:
        db.close()

# ---------------- ADMIN ----------------
ADMIN_PASSWORD = "PHIL4857"

@app.post("/admin/login")
def admin_login(password: str = Form(...)):
    if password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin password")
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
                "referral": u.referral
            } for u in users
        ]
    finally:
        db.close()

@app.post("/admin/approve-user")
def admin_approve_user(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.approved = True
        db.commit()
        db.refresh(user)
        return {"message": f"User {username} approved successfully"}
    finally:
        db.close()

@app.post("/admin/approve-withdrawal")
def admin_approve_withdrawal(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        pending = PENDING_WITHDRAWALS.pop(username.strip(), None)
        if not user or not pending:
            raise HTTPException(status_code=400, detail="No pending withdrawal for this user")
        if user.balance < pending["amount"]:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        user.balance -= pending["amount"]
        db.commit()
        db.refresh(user)
        return {"message": f"Withdrawal for {username} approved and processed"}
    finally:
        db.close()

@app.post("/admin/terminate-user")
def admin_terminate_user(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        PENDING_INVESTMENTS.pop(username.strip(), None)
        PENDING_WITHDRAWALS.pop(username.strip(), None)

        db.delete(user)
        db.commit()

        logger.info(f"Admin terminated user: {username}")
        return {"message": f"User {username} has been terminated and all data removed."}
    finally:
        db.close()

@app.post("/admin/reset-password")
def admin_reset_password(username: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username.strip()).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

        user.password_hash = hash_pwd(new_password)
        db.commit()
        db.refresh(user)

        logger.info(f"Admin reset password for {username}")
        return {"message": "Password reset successful", "new_password": new_password}
    finally:
        db.close()
