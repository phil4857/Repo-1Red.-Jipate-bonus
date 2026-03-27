import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, constr, validator
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, JSON, DateTime
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import bcrypt
import jwt

# ---------------- Config & Logging ----------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("mkoba-backend")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
SECRET_KEY = os.getenv("SECRET_KEY", "replace-me-with-secure-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "PHIL4857")
MPESA_NUMBER = os.getenv("MPESA_NUMBER", "0752964507")
REFERRAL_BONUS_PERCENT = float(os.getenv("REFERRAL_BONUS_PERCENT", "10"))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")
origins = ["*"] if ALLOWED_ORIGINS == "*" else [o.strip() for o in ALLOWED_ORIGINS.split(",")]

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

# ---------------- App & DB ----------------
app = FastAPI(title="Mkoba Wallet Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ---------------- Models ----------------
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, nullable=False, index=True)
    phone = Column(String(50), nullable=False)
    password_hash = Column(String(200), nullable=False)
    approved = Column(Boolean, default=False)
    balance = Column(Float, default=0.0)
    earnings = Column(Float, default=0.0)
    investments = Column(JSON, default=lambda: {})
    referral_code = Column(String(150), nullable=True)
    referral_bonus_earned = Column(Float, default=0.0)


class WithdrawalRequest(Base):
    __tablename__ = "withdrawal_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String(50), default="pending")
    requested_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)


Base.metadata.create_all(bind=engine)

# ---------------- Schemas ----------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=50, regex=r"^[a-zA-Z0-9_.-]+$")
    phone: constr(strip_whitespace=True, min_length=6, max_length=20)
    password: constr(min_length=6, max_length=128)
    referral: Optional[constr(strip_whitespace=True, min_length=3, max_length=50)] = None

    @validator("username")
    def lower_username(cls, v):
        return v.lower()


class UserLogin(BaseModel):
    username: constr(strip_whitespace=True, min_length=3)
    password: constr(min_length=6)


class DashboardResponse(BaseModel):
    username: str
    balance: float
    earnings: float
    investments: Dict[str, Any]
    daily_earnings: float
    approved: bool
    referral_link: Optional[str] = None
    referral_bonus_earned: Optional[float] = 0.0


class InvestRequest(BaseModel):
    commodity: constr(strip_whitespace=True)


class WithdrawRequestSchema(BaseModel):
    amount: float = Field(..., ge=0)

# ---------------- Helpers ----------------
def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserDB:
    payload = decode_access_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth payload")
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

# ---------------- Routes ----------------
@app.get("/", tags=["root"])
def root():
    return {"status": "online", "message": "Mkoba Wallet API running"}

@app.post("/register", response_model=dict, status_code=201, tags=["auth"])
def register(payload: UserCreate = Body(...), db: Session = Depends(get_db)):
    username = payload.username
    phone = payload.phone
    password = payload.password
    referral = payload.referral.strip().lower() if payload.referral else None
    if db.query(UserDB).filter(UserDB.username == username).first():
        raise HTTPException(status_code=400, detail="Username exists")
    hashed_pw = hash_pwd(password)
    user = UserDB(username=username, phone=phone, password_hash=hashed_pw, referral_code=referral)
    db.add(user)
    db.commit()
    db.refresh(user)
    link = f"https://mkobawallets.vercel.app/register.html?ref={username}"
    return {"message": "User registered. Awaiting approval.", "referral_link": link}

@app.post("/login", response_model=Token, tags=["auth"])
def login(payload: UserLogin = Body(...), db: Session = Depends(get_db)):
    username = payload.username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user or not check_pwd(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not user.approved:
        raise HTTPException(status_code=403, detail="Account not approved")
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/dashboard", response_model=DashboardResponse, tags=["user"])
def dashboard(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    user = current_user
    investments = user.investments or {}
    now = datetime.utcnow()
    inv_status = {}
    daily_earnings = 0.0
    for commodity, inv in investments.items():
        try:
            start = datetime.fromisoformat(inv["start_date"])
            expiry = datetime.fromisoformat(inv["expiry_date"])
            last = datetime.fromisoformat(inv.get("last_credited", start.isoformat()))
        except Exception:
            continue
        days_total = COMMODITY_INFO.get(commodity, {}).get("expiry_days", 1)
        daily_rate = inv["amount"]/days_total
        days_to_credit = (now-last).days
        if days_to_credit>0:
            user.balance += daily_rate*days_to_credit
            user.earnings += daily_rate*days_to_credit
            inv["last_credited"] = now.isoformat()
        inv_status[commodity] = {
            "amount": inv.get("amount",0),
            "days_remaining": max((expiry-now).days,0),
            "daily_earning": daily_rate
        }
        daily_earnings += daily_rate
    try:
        user.investments = investments
        db.add(user)
        db.commit()
        db.refresh(user)
    except SQLAlchemyError:
        db.rollback()
    return DashboardResponse(
        username=user.username,
        balance=user.balance or 0,
        earnings=user.earnings or 0,
        investments=inv_status,
        daily_earnings=daily_earnings,
        approved=user.approved,
        referral_link=f"https://mkobawallets.vercel.app/register.html?ref={user.username}",
        referral_bonus_earned=user.referral_bonus_earned or 0,
    )

# ---------------- Investment ----------------
@app.post("/invest/request", response_model=dict, tags=["invest"])
def invest_request(payload: InvestRequest = Body(...)):
    commodity = payload.commodity.strip().lower()
    if commodity not in COMMODITY_INFO:
        raise HTTPException(400,"Invalid commodity")
    return {"message":"Send payment to M-Pesa","price":COMMODITY_INFO[commodity]["price"],"mpesa_number":MPESA_NUMBER}

@app.post("/invest/confirm", response_model=dict, tags=["invest"])
def invest_confirm(payload: InvestRequest = Body(...), db: Session=Depends(get_db), current_user: UserDB=Depends(get_current_user)):
    commodity = payload.commodity.strip().lower()
    if commodity not in COMMODITY_INFO:
        raise HTTPException(400,"Invalid commodity")
    price = COMMODITY_INFO[commodity]["price"]
    user = current_user
    investments = dict(user.investments or {})
    if commodity in investments:
        raise HTTPException(400,"Already invested in this commodity")
    now = datetime.utcnow()
    investments[commodity] = {
        "amount": price,
        "start_date": now.isoformat(),
        "expiry_date": (now+timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])).isoformat(),
        "last_credited": now.isoformat()
    }
    user.investments = investments
    if user.referral_code:
        ref = db.query(UserDB).filter(UserDB.username==user.referral_code).first()
        if ref:
            bonus = price*(REFERRAL_BONUS_PERCENT/100)
            ref.earnings += bonus
            ref.referral_bonus_earned += bonus
            db.add(ref)
    db.add(user)
    db.commit()
    return {"message":f"Investment in {commodity} confirmed"}

# ---------------- Withdraw ----------------
@app.post("/withdraw/request", response_model=dict, tags=["withdraw"])
def withdraw_request(payload: WithdrawRequestSchema=Body(...), db: Session=Depends(get_db), current_user: UserDB=Depends(get_current_user)):
    amount = payload.amount
    if amount < 500:
        raise HTTPException(400,"Minimum withdrawal is KES 500")
    if (current_user.balance or 0)<amount:
        raise HTTPException(400,"Insufficient balance")
    req = WithdrawalRequest(user_id=current_user.id, amount=amount)
    db.add(req)
    db.commit()
    return {"message":"Withdrawal request submitted"}

# ---------------- Admin ----------------
@app.get("/admin/users", response_model=list, tags=["admin"])
def admin_get_users(admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    users = db.query(UserDB).all()
    result = []
    for u in users:
        result.append({
            "username": u.username,
            "phone": u.phone,
            "approved": u.approved,
            "balance": u.balance,
            "earnings": u.earnings,
            "referral_link": f"https://mkobawallets.vercel.app/register.html?ref={u.username}",
            "referral_bonus_earned": u.referral_bonus_earned
        })
    return result

@app.get("/admin/withdrawals/pending", response_model=list, tags=["admin"])
def admin_get_withdrawals(admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    requests = db.query(WithdrawalRequest).filter(WithdrawalRequest.status=="pending").all()
    result=[]
    for r in requests:
        u=db.query(UserDB).filter(UserDB.id==r.user_id).first()
        result.append({
            "id": r.id,
            "username": u.username,
            "amount": r.amount,
            "method":"M-Pesa",
            "account": u.phone,
            "requested_at": r.requested_at.isoformat()
        })
    return result

@app.post("/admin/approve-user", response_model=dict, tags=["admin"])
def admin_approve_user(username: str = Body(...), admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    user=db.query(UserDB).filter(UserDB.username==username.strip().lower()).first()
    if not user: raise HTTPException(404,"User not found")
    user.approved=True
    db.add(user)
    db.commit()
    return {"message":f"User {username} approved"}

@app.post("/admin/reset-password", response_model=dict, tags=["admin"])
def admin_reset_password(username: str = Body(...), admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    user=db.query(UserDB).filter(UserDB.username==username.strip().lower()).first()
    if not user: raise HTTPException(404,"User not found")
    user.password_hash = hash_pwd("default123")  # default reset password
    db.add(user)
    db.commit()
    return {"message":f"Password reset for {username}"}

@app.post("/admin/terminate-user", response_model=dict, tags=["admin"])
def admin_terminate_user(username: str = Body(...), admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    user=db.query(UserDB).filter(UserDB.username==username.strip().lower()).first()
    if not user: raise HTTPException(404,"User not found")
    db.delete(user)
    db.commit()
    return {"message":f"User {username} terminated"}

@app.post("/admin/withdrawals/approve", response_model=dict, tags=["admin"])
def admin_approve_withdrawal(id: int = Body(...), admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    req=db.query(WithdrawalRequest).filter(WithdrawalRequest.id==id).first()
    if not req: raise HTTPException(404,"Request not found")
    req.status="approved"
    req.approved_at=datetime.utcnow()
    user=db.query(UserDB).filter(UserDB.id==req.user_id).first()
    user.balance -= req.amount
    db.add(user)
    db.add(req)
    db.commit()
    return {"message":"Withdrawal approved"}

@app.post("/admin/withdrawals/reject", response_model=dict, tags=["admin"])
def admin_reject_withdrawal(id: int = Body(...), admin_password: str = Body(...), db: Session=Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401,"Invalid admin password")
    req=db.query(WithdrawalRequest).filter(WithdrawalRequest.id==id).first()
    if not req: raise HTTPException(404,"Request not found")
    req.status="rejected"
    db.add(req)
    db.commit()
    return {"message":"Withdrawal rejected"}

# ---------------- OAuth2 token ----------------
@app.post("/token", response_model=Token, tags=["auth"])
def token_for_oauth2(payload: UserLogin=Body(...), db: Session=Depends(get_db)):
    username=payload.username.strip().lower()
    user=db.query(UserDB).filter(UserDB.username==username).first()
    if not user or not check_pwd(payload.password, user.password_hash):
        raise HTTPException(401,"Invalid credentials")
    if not user.approved:
        raise HTTPException(403,"Account not approved")
    token=create_access_token({"sub":username})
    return {"access_token":token, "token_type":"bearer"}
