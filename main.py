import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, constr, validator
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, JSON, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.ext.mutable import MutableDict
import bcrypt
import jwt

# ---------------- CONFIG ----------------
DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "CHANGE_THIS_SECRET_TO_A_STRONG_RANDOM_VALUE_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ADMIN_PASSWORD = "PHIL4857"
REFERRAL_BONUS_PERCENT = 10

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

# ---------------- APP ----------------
app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DATABASE ----------------
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

# ---------------- MODELS ----------------
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    phone = Column(String)
    password_hash = Column(String)
    approved = Column(Boolean, default=True)
    balance = Column(Float, default=0.0)
    earnings = Column(Float, default=0.0)
    investments = Column(MutableDict.as_mutable(JSON), default=dict)
    referral_code = Column(String, nullable=True)
    referral_bonus_earned = Column(Float, default=0.0)

class WithdrawalRequest(Base):
    __tablename__ = "withdrawals"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    amount = Column(Float)
    status = Column(String, default="pending")
    requested_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

# ---------------- HELPERS ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def create_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserDB:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(UserDB).filter_by(username=username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------------- SCHEMAS ----------------
class UserCreate(BaseModel):
    username: constr(min_length=3)
    phone: str
    password: constr(min_length=6)
    referral: Optional[str] = None

    @validator("username")
    def lower_username(cls, v):
        return v.lower()

class UserLogin(BaseModel):
    username: str
    password: str

class InvestRequest(BaseModel):
    commodity: str

class WithdrawRequest(BaseModel):
    amount: float

class AdminAction(BaseModel):
    password: str
    username: Optional[str] = None
    withdrawal_id: Optional[int] = None
    investment_commodity: Optional[str] = None

# ---------------- ADMIN ROUTES (unchanged) ----------------
@app.post("/admin/login")
def admin_login(data: UserLogin = Body(...)):
    if data.username != "admin" or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    token = create_token({"sub": "admin", "role": "admin"})
    return {"success": True, "message": "Admin login successful", "access_token": token, "token_type": "bearer"}

@app.post("/admin/users")
def get_admin_users(data: dict = Body(...), db: Session = Depends(get_db)):
    if data.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    users = db.query(UserDB).all()
    return [{
        "id": u.id,
        "username": u.username,
        "phone": u.phone,
        "approved": u.approved,
        "balance": u.balance,
        "earnings": u.earnings,
    } for u in users]

@app.post("/admin/reset-password")
def reset_password(data: AdminAction = Body(...), db: Session = Depends(get_db)):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    if not data.username:
        raise HTTPException(status_code=400, detail="username is required")
    user = db.query(UserDB).filter_by(username=data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{data.username}' not found")
    user.password_hash = hash_pwd("123456")
    db.commit()
    return {"message": f"Password for {data.username} reset to '123456'"}

@app.post("/admin/terminate-user")
def terminate_user(data: AdminAction = Body(...), db: Session = Depends(get_db)):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    if not data.username:
        raise HTTPException(status_code=400, detail="username is required")
    user = db.query(UserDB).filter_by(username=data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{data.username}' not found")
    db.delete(user)
    db.commit()
    return {"message": f"User {data.username} has been terminated"}

@app.post("/admin/withdrawals")
def get_withdrawals(data: dict = Body(...), db: Session = Depends(get_db)):
    if data.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    withdrawals = db.query(WithdrawalRequest).all()
    result = []
    for w in withdrawals:
        user = db.query(UserDB).filter_by(id=w.user_id).first()
        result.append({
            "id": w.id,
            "username": user.username if user else "Unknown",
            "amount": w.amount,
            "status": w.status,
            "requested_at": w.requested_at.isoformat() if w.requested_at else None
        })
    return result

@app.post("/admin/withdraw_approve")
def approve_withdrawal(data: AdminAction = Body(...), db: Session = Depends(get_db)):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    if not data.withdrawal_id:
        raise HTTPException(status_code=400, detail="withdrawal_id is required")
    withdrawal = db.query(WithdrawalRequest).filter_by(id=data.withdrawal_id).first()
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal request not found")
    if withdrawal.status != "pending":
        raise HTTPException(status_code=400, detail="Withdrawal already processed")
    withdrawal.status = "approved"
    withdrawal.approved_at = datetime.utcnow()
    user = db.query(UserDB).filter_by(id=withdrawal.user_id).first()
    if user and user.balance >= withdrawal.amount:
        user.balance -= withdrawal.amount
    else:
        raise HTTPException(status_code=400, detail="Insufficient balance or user not found")
    db.commit()
    return {"message": f"Withdrawal #{data.withdrawal_id} approved successfully"}

@app.post("/admin/approve-investment")
def approve_investment(data: AdminAction = Body(...), db: Session = Depends(get_db)):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    if not data.username or not data.investment_commodity:
        raise HTTPException(status_code=400, detail="username and investment_commodity are required")
    
    user = db.query(UserDB).filter_by(username=data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{data.username}' not found")
    
    investments = user.investments or {}
    if data.investment_commodity not in investments:
        raise HTTPException(status_code=404, detail="Investment not found for this user")
    
    investment = investments[data.investment_commodity]
    if investment.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Investment already processed")
    
    investment["status"] = "approved"
    investment["start_date"] = datetime.utcnow().isoformat()
    investment["expiry_date"] = (datetime.utcnow() + timedelta(days=COMMODITY_INFO[data.investment_commodity]["expiry_days"])).isoformat()
    investment["last_credited"] = datetime.utcnow().isoformat()

    user.investments = investments   # Important for MutableDict
    
    # Referral bonus
    if user.referral_code:
        referrer = db.query(UserDB).filter_by(username=user.referral_code).first()
        if referrer:
            bonus = investment.get("amount", 0) * (REFERRAL_BONUS_PERCENT / 100)
            referrer.referral_bonus_earned = (referrer.referral_bonus_earned or 0) + bonus
            referrer.balance = (referrer.balance or 0) + bonus
            db.add(referrer)
    
    db.commit()
    db.refresh(user)
    return {"message": f"Investment in {data.investment_commodity} for {data.username} approved successfully. Earnings will start now."}

@app.post("/admin/pending-investments")
def get_pending_investments(data: dict = Body(...), db: Session = Depends(get_db)):
    if data.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    
    users = db.query(UserDB).all()
    pending = []
    
    for user in users:
        investments = user.investments or {}
        for commodity, inv in investments.items():
            if inv.get("status") == "pending":
                pending.append({
                    "username": user.username,
                    "commodity": commodity,
                    "amount": inv.get("amount", 0),
                    "requested_at": inv.get("requested_at", "N/A")
                })
    
    return pending

# ==================== FIXED INVESTMENT REQUEST ====================
@app.post("/invest/request")
def invest_request(data: InvestRequest, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    price = COMMODITY_INFO[data.commodity]["price"]

    investments = current_user.investments or {}

    # Prevent duplicate pending investment for same commodity
    if data.commodity in investments and investments[data.commodity].get("status") == "pending":
        raise HTTPException(status_code=400, detail="You already have a pending request for this commodity")

    investments[data.commodity] = {
        "amount": price,
        "status": "pending",
        "payment_method": f"Pay via M-Pesa to {MPESA_NUMBER}",
        "requested_at": datetime.utcnow().isoformat()
    }

    current_user.investments = investments
    db.commit()
    db.refresh(current_user)

    return {
        "success": True,
        "message": f"Request for {data.commodity} submitted successfully.",
        "commodity": data.commodity,
        "price": price,
        "payment_instruction": f"Pay KES {price} via M-Pesa to {MPESA_NUMBER}",
        "status": "pending"
    }

# ---------------- WITHDRAW REQUEST ----------------
@app.post("/withdraw/request")
def request_withdrawal(data: WithdrawRequest, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")
    if current_user.balance < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    withdrawal = WithdrawalRequest(
        user_id=current_user.id,
        amount=data.amount
    )
    db.add(withdrawal)
    db.commit()

    return {"message": "Withdrawal request submitted. Waiting for admin approval."}

# ---------------- AUTH ROUTES (unchanged) ----------------
@app.post("/register")
def register(data: UserCreate = Body(...), db: Session = Depends(get_db)):
    if db.query(UserDB).filter_by(username=data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = UserDB(
        username=data.username,
        phone=data.phone,
        password_hash=hash_pwd(data.password),
        referral_code=data.referral.lower() if data.referral else None,
        approved=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Registered successfully. You can login immediately.",
        "referral_link": f"https://jipate-bonus-v1.vercel.app/register.html?ref={data.username}"
    }

@app.post("/login")
def login(data: UserLogin = Body(...), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter_by(username=data.username.lower()).first()
    if not user or not check_pwd(data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    token = create_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# ---------------- DASHBOARD (unchanged) ----------------
@app.get("/dashboard")
def dashboard(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    # ... (your existing dashboard code remains the same)
    user = current_user
    now = datetime.utcnow()
    daily_earnings = 0
    inv_status = {}

    investments = user.investments or {}

    for commodity in COMMODITY_INFO:
        inv = investments.get(commodity, {})
        status = inv.get("status", "not_invested")
        amount = inv.get("amount", 0)

        if status == "approved":
            try:
                start = datetime.fromisoformat(inv.get("start_date", datetime.utcnow().isoformat()))
                expiry = datetime.fromisoformat(inv.get("expiry_date", datetime.utcnow().isoformat()))
                last = datetime.fromisoformat(inv.get("last_credited", start.isoformat()))
            except:
                start = datetime.utcnow()
                expiry = start + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])
                last = start

            days_total = COMMODITY_INFO[commodity]["expiry_days"]
            daily_rate = amount / days_total
            days_to_credit = max((now - last).days, 0)

            if days_to_credit > 0:
                earned = daily_rate * days_to_credit
                user.balance += earned
                user.earnings += earned
                inv["last_credited"] = now.isoformat()

            seconds_since_last = (now - last).total_seconds()
            seconds_to_next = 86400 - (seconds_since_last % 86400)
            hours_to_next = int(seconds_to_next // 3600)
            minutes_to_next = int((seconds_to_next % 3600) // 60)

            inv_status[commodity] = {
                "amount": amount,
                "status": "approved",
                "emoji": "✅",
                "days_remaining": max((expiry - now).days, 0),
                "daily_earning": daily_rate,
                "time_to_next_earning": f"{hours_to_next}h {minutes_to_next}m until next earning"
            }
            daily_earnings += daily_rate
        elif status == "pending":
            inv_status[commodity] = {
                "amount": amount,
                "status": "pending",
                "emoji": "🕒",
                "payment_instruction": inv.get("payment_method", f"Pay via M-Pesa to {MPESA_NUMBER}")
            }
        else:
            inv_status[commodity] = {
                "amount": amount,
                "status": "not_invested",
                "emoji": "🔄",
                "payment_instruction": f"Pay via M-Pesa to {MPESA_NUMBER}"
            }

    referral_bonus = user.referral_bonus_earned

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "username": user.username,
        "balance": user.balance,
        "earnings": user.earnings,
        "investments": inv_status,
        "daily_earnings": daily_earnings,
        "approved": user.approved,
        "referral_link": f"https://jipate-bonus-v1.vercel.app/register.html?ref={user.username}",
        "referral_bonus_earned": referral_bonus
    }

# ---------------- RUN ----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
