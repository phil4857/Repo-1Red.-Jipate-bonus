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
from sqlalchemy.orm.attributes import flag_modified
import bcrypt
import jwt

# ---------------- CONFIG ----------------
DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "CHANGE_THIS_SECRET_TO_A_STRONG_RANDOM_VALUE_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ADMIN_PASSWORD = "PHIL4857"
REFERRAL_BONUS_PERCENT = 10
WITHDRAWAL_CHARGE_PERCENT = 20

# ✅ UPDATED TO MATCH FRONTEND EXACTLY
COMMODITY_INFO = {
    "data_pack":      {"price": 1000, "daily_bonus": 100, "expiry_days": 15},
    "creator":        {"price": 1400, "daily_bonus": 140, "expiry_days": 20},
    "affiliate":      {"price": 1800, "daily_bonus": 180, "expiry_days": 23},
    "influencer":     {"price": 2200, "daily_bonus": 220, "expiry_days": 25},
    "digital_pro":    {"price": 2600, "daily_bonus": 260, "expiry_days": 28},
    "growth_hub":     {"price": 3000, "daily_bonus": 300, "expiry_days": 32},
    "wealth_builder": {"price": 3500, "daily_bonus": 350, "expiry_days": 35},
    "empire":         {"price": 4000, "daily_bonus": 400, "expiry_days": 45},
}

MPESA_NUMBER = "0752964507"

# 🌐 UPDATED FRONTEND URL
FRONTEND_URL = "https://mula-hyum72b8o-voting-219fda77.vercel.app"

# ---------------- APP ----------------
app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
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
    charge = Column(Float, default=0.0)
    net_amount = Column(Float, default=0.0)
    payment_method = Column(String, default="mpesa")
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

class GrabBonusRequest(BaseModel):
    commodity: str

class WithdrawRequest(BaseModel):
    amount: float
    payment_method: str = "mpesa"

class AdminAction(BaseModel):
    password: str
    username: Optional[str] = None
    withdrawal_id: Optional[int] = None
    investment_commodity: Optional[str] = None

# ---------------- ADMIN ROUTES ----------------
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
            "charge": w.charge,
            "net_amount": w.net_amount,
            "payment_method": w.payment_method,
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

# ---------------- INVESTMENT REQUEST ----------------
@app.post("/invest/request")
def invest_request(data: InvestRequest, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    price = COMMODITY_INFO[data.commodity]["price"]
    investments = current_user.investments or {}

    if data.commodity in investments and investments[data.commodity].get("status") == "pending":
        raise HTTPException(status_code=400, detail="You already have a pending request for this commodity")

    investments[data.commodity] = {
        "amount": price,
        "status": "pending",
        "payment_method": f"Pay via M-Pesa to {MPESA_NUMBER}",
        "requested_at": datetime.utcnow().isoformat()
    }

    current_user.investments = investments
    flag_modified(current_user, "investments")
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

# ---------------- BONUS ----------------
@app.post("/bonus/grab")
def grab_bonus(data: GrabBonusRequest, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    commodity = data.commodity
    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    investments = current_user.investments or {}
    inv = investments.get(commodity, {})

    if inv.get("status") != "approved":
        raise HTTPException(status_code=400, detail="Investment not approved yet")

    now = datetime.utcnow()
    try:
        last_credited = datetime.fromisoformat(inv.get("last_credited"))
    except:
        last_credited = now - timedelta(days=2)

    if (now - last_credited).total_seconds() < 86400:
        raise HTTPException(status_code=400, detail="Bonus not ready yet")

    earned = COMMODITY_INFO[commodity]["daily_bonus"]

    current_user.balance += earned
    current_user.earnings += earned

    inv["last_credited"] = now.isoformat()
    flag_modified(current_user, "investments")

    db.commit()
    db.refresh(current_user)

    return {
        "success": True,
        "message": f"Successfully grabbed KES {earned} daily bonus for {commodity}!",
        "earned": earned,
        "new_balance": round(current_user.balance, 2)
    }

# ---------------- WITHDRAW ----------------
@app.post("/withdraw/request")
def request_withdrawal(data: WithdrawRequest, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")

    charge = data.amount * (WITHDRAWAL_CHARGE_PERCENT / 100)
    net_amount = data.amount - charge

    if current_user.balance < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    valid_methods = ["mpesa", "bank", "paypal"]
    if data.payment_method.lower() not in valid_methods:
        raise HTTPException(status_code=400, detail="Invalid payment method")

    withdrawal = WithdrawalRequest(
        user_id=current_user.id,
        amount=data.amount,
        charge=charge,
        net_amount=net_amount,
        payment_method=data.payment_method.lower()
    )

    db.add(withdrawal)
    db.commit()

    return {
        "message": f"Withdrawal request submitted. You will receive KES {net_amount:.2f} after approval."
    }

# ---------------- AUTH ----------------
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
        "message": "Registered successfully.",
        "referral_link": f"{FRONTEND_URL}/register.html?ref={data.username}"
    }

@app.post("/login")
def login(data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter_by(username=data.username.lower()).first()
    if not user or not check_pwd(data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# ---------------- DASHBOARD ----------------
@app.get("/dashboard")
def dashboard(current_user: UserDB = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "balance": round(current_user.balance, 2),
        "earnings": round(current_user.earnings, 2),
        "investments": current_user.investments or {},
        "referral_bonus_earned": round(current_user.referral_bonus_earned or 0, 2),
        "referral_link": f"{FRONTEND_URL}/register.html?ref={current_user.username}"
    }

# ---------------- RUN ----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
