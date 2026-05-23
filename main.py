import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Body
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

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mulahub.db")
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_SECRET_TO_A_STRONG_RANDOM_VALUE_IN_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "PHIL4857")
REFERRAL_BONUS_PERCENT = 10
WITHDRAWAL_CHARGE_PERCENT = 20

# ✅ ALIGNED WITH FRONTEND: exact keys & prices from dashboard.html COMMODITY_INFO
COMMODITY_INFO = {
    "spark": {
        "price": 450,
        "daily_bonus": 40,
        "expiry_days": 18
    },

    "boost": {
        "price": 550,
        "daily_bonus": 50,
        "expiry_days": 20
    },

    "connect": {
        "price": 650,
        "daily_bonus": 60,
        "expiry_days": 22
    },

    "stream": {
        "price": 750,
        "daily_bonus": 70,
        "expiry_days": 24
    },

    "launch": {
        "price": 900,
        "daily_bonus": 85,
        "expiry_days": 26
    },

    "data_pack": {
        "price": 1000,
        "daily_bonus": 100,
        "expiry_days": 20
    },

    "creator": {
        "price": 1400,
        "daily_bonus": 140,
        "expiry_days": 23
    },

    "affiliate": {
        "price": 1800,
        "daily_bonus": 180,
        "expiry_days": 25
    },

    "influencer": {
        "price": 2200,
        "daily_bonus": 220,
        "expiry_days": 28
    },

    "digital_pro": {
        "price": 2600,
        "daily_bonus": 260,
        "expiry_days": 30
    },

    "growth_hub": {
        "price": 3000,
        "daily_bonus": 300,
        "expiry_days": 35
    },

    "wealth_builder": {
        "price": 3500,
        "daily_bonus": 350,
        "expiry_days": 40
    },

    "empire": {
        "price": 4000,
        "daily_bonus": 400,
        "expiry_days": 45
    },
}

# ✅ ALIGNED WITH FRONTEND: referral link base URL
FRONTEND_URL = "https://mula-hub.vercel.app/"
MPESA_NUMBER = "0752964507"

# ---------------- APP ----------------

app = FastAPI(title="MulaHub Backend")

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
    charge = Column(Float, default=0.0)
    net_amount = Column(Float, default=0.0)
    payment_method = Column(String, default="mpesa")
    account_number = Column(String, nullable=True)
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
        return v.lower().strip()

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
    account_number: Optional[str] = None

class AdminAction(BaseModel):
    password: str
    username: Optional[str] = None
    withdrawal_id: Optional[int] = None
    investment_commodity: Optional[str] = None

# ================================================================
#  AUTH ROUTES
# ================================================================

@app.post("/register")
def register(data: UserCreate = Body(...), db: Session = Depends(get_db)):
    if db.query(UserDB).filter_by(username=data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    # Validate referral exists
    referral_code = None
    if data.referral:
        ref = data.referral.lower().strip()
        if db.query(UserDB).filter_by(username=ref).first():
            referral_code = ref
        # If referral not found, silently ignore (don't error)

    user = UserDB(
        username=data.username,
        phone=data.phone,
        password_hash=hash_pwd(data.password),
        referral_code=referral_code,
        approved=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "success": True,
        "message": "Account created successfully. You can login now 🚀",
        "referral_link": f"{FRONTEND_URL}/register.html?ref={data.username}",
    }


@app.post("/login")
def login(data: UserLogin = Body(...), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter_by(username=data.username.lower().strip()).first()
    if not user or not check_pwd(data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    token = create_token({"sub": user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,   # ✅ Frontend stores this in localStorage
    }

# ================================================================
#  DASHBOARD
# ================================================================

@app.get("/dashboard")
def dashboard(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = current_user
    now = datetime.utcnow()
    investments = user.investments or {}
    inv_status = {}

    for commodity, info in COMMODITY_INFO.items():
        inv = investments.get(commodity, {})
        status = inv.get("status", "not_invested")
        amount = inv.get("amount", 0.0)

        if status == "approved":
            try:
                expiry = datetime.fromisoformat(inv["expiry_date"])
                last = datetime.fromisoformat(inv.get("last_credited", (now - timedelta(days=2)).isoformat()))
            except Exception:
                expiry = now + timedelta(days=info["expiry_days"])
                last = now - timedelta(days=2)

            can_grab = (now - last).total_seconds() >= 86400
            seconds_to_next = max(0, 86400 - (now - last).total_seconds())
            hours_to_next = int(seconds_to_next // 3600)
            minutes_to_next = int((seconds_to_next % 3600) // 60)

            inv_status[commodity] = {
                "amount": amount,
                "status": "approved",
                "daily_earning": info["daily_bonus"],
                "days_remaining": max((expiry - now).days, 0),
                "can_grab": can_grab,
                "time_to_next": "Ready to grab now!" if can_grab else f"{hours_to_next}h {minutes_to_next}m",
            }

        elif status == "pending":
            inv_status[commodity] = {
                "amount": amount,
                "status": "pending",
                "payment_instruction": f"Pay KES {amount} via M-Pesa to {MPESA_NUMBER}. Include your username.",
            }

    return {
        "username": user.username,
        "balance": round(user.balance, 2),
        "earnings": round(user.earnings, 2),
        "referral_bonus_earned": round(user.referral_bonus_earned or 0.0, 2),
        "investments": inv_status,
        "referral_link": f"{FRONTEND_URL}/register.html?ref={user.username}",
        "approved": user.approved,
    }

# ================================================================
#  INVEST REQUEST
# ================================================================

@app.post("/invest/request")
def invest_request(
    data: InvestRequest,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if data.commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid plan selected")

    info = COMMODITY_INFO[data.commodity]
    investments = current_user.investments or {}

    existing = investments.get(data.commodity, {})
    if existing.get("status") == "pending":
        raise HTTPException(status_code=400, detail="You already have a pending request for this plan")
    if existing.get("status") == "approved":
        raise HTTPException(status_code=400, detail="You already have an active plan of this type")

    investments[data.commodity] = {
        "amount": info["price"],
        "status": "pending",
        "requested_at": datetime.utcnow().isoformat(),
        "payment_instruction": f"Pay KES {info['price']} via M-Pesa to {MPESA_NUMBER}. Include your username.",
    }

    current_user.investments = investments
    flag_modified(current_user, "investments")
    db.commit()

    return {
        "success": True,
        "message": f"Plan request submitted! Pay KES {info['price']} via M-Pesa to {MPESA_NUMBER} and include your username.",
        "commodity": data.commodity,
        "price": info["price"],
        "status": "pending",
    }

# ================================================================
#  GRAB DAILY BONUS
# ================================================================

@app.post("/bonus/grab")
def grab_bonus(
    data: GrabBonusRequest,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if data.commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid plan")

    investments = current_user.investments or {}
    inv = investments.get(data.commodity, {})

    if inv.get("status") != "approved":
        raise HTTPException(status_code=400, detail="This plan is not approved yet")

    now = datetime.utcnow()
    try:
        last_credited = datetime.fromisoformat(inv["last_credited"])
    except Exception:
        last_credited = now - timedelta(days=2)

    seconds_since = (now - last_credited).total_seconds()
    if seconds_since < 86400:
        remaining = 86400 - seconds_since
        h = int(remaining // 3600)
        m = int((remaining % 3600) // 60)
        raise HTTPException(status_code=400, detail=f"Next bonus available in {h}h {m}m")

    # Check expiry
    try:
        expiry = datetime.fromisoformat(inv["expiry_date"])
        if now > expiry:
            raise HTTPException(status_code=400, detail="This plan has expired")
    except KeyError:
        pass

    daily_bonus = COMMODITY_INFO[data.commodity]["daily_bonus"]
    current_user.balance = (current_user.balance or 0.0) + daily_bonus
    current_user.earnings = (current_user.earnings or 0.0) + daily_bonus

    inv["last_credited"] = now.isoformat()
    current_user.investments = investments
    flag_modified(current_user, "investments")
    db.commit()

    return {
        "success": True,
        "message": f"✅ KES {daily_bonus} daily bonus added to your balance!",
        "earned": daily_bonus,
        "new_balance": round(current_user.balance, 2),
    }

# ================================================================
#  WITHDRAWAL REQUEST
# ================================================================

@app.post("/withdraw/request")
def request_withdrawal(
    data: WithdrawRequest,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if data.amount < 100:
        raise HTTPException(status_code=400, detail="Minimum withdrawal is KES 100")

    if current_user.balance < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    valid_methods = ["mpesa", "bank", "paypal"]
    if data.payment_method.lower() not in valid_methods:
        raise HTTPException(status_code=400, detail="Invalid payment method. Choose: mpesa, bank, or paypal")

    charge = data.amount * (WITHDRAWAL_CHARGE_PERCENT / 100)
    net_amount = data.amount - charge

    withdrawal = WithdrawalRequest(
        user_id=current_user.id,
        amount=data.amount,
        charge=charge,
        net_amount=net_amount,
        payment_method=data.payment_method.lower(),
        account_number=data.account_number,
    )
    db.add(withdrawal)
    db.commit()

    return {
        "success": True,
        "message": (
            f"Withdrawal request of KES {data.amount} submitted. "
            f"20% charge: KES {charge:.2f}. "
            f"You will receive KES {net_amount:.2f} via {data.payment_method.upper()} after admin approval."
        ),
    }

# ================================================================
#  ADMIN ROUTES
# ================================================================

@app.post("/admin/login")
def admin_login(data: UserLogin = Body(...)):
    if data.username != "admin" or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    token = create_token({"sub": "admin", "role": "admin"})
    return {"success": True, "access_token": token, "token_type": "bearer"}


@app.post("/admin/users")
def get_admin_users(data: dict = Body(...), db: Session = Depends(get_db)):
    if data.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    users = db.query(UserDB).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "phone": u.phone,
            "approved": u.approved,
            "balance": round(u.balance, 2),
            "earnings": round(u.earnings, 2),
            "referral_bonus_earned": round(u.referral_bonus_earned or 0.0, 2),
            "referral_code": u.referral_code,
        }
        for u in users
    ]


@app.post("/admin/pending-investments")
def get_pending_investments(data: dict = Body(...), db: Session = Depends(get_db)):
    if data.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    users = db.query(UserDB).all()
    pending = []
    for user in users:
        for commodity, inv in (user.investments or {}).items():
            if inv.get("status") == "pending":
                pending.append({
                    "username": user.username,
                    "phone": user.phone,
                    "commodity": commodity,
                    "amount": inv.get("amount", 0),
                    "requested_at": inv.get("requested_at", "N/A"),
                })
    return pending


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
    commodity = data.investment_commodity

    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity/plan")

    inv = investments.get(commodity)
    if not inv:
        raise HTTPException(status_code=404, detail="Investment not found for this user")
    if inv.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Investment is not in pending state")

    info = COMMODITY_INFO[commodity]
    now = datetime.utcnow()

    inv["status"] = "approved"
    inv["start_date"] = now.isoformat()
    inv["expiry_date"] = (now + timedelta(days=info["expiry_days"])).isoformat()
    inv["last_credited"] = (now - timedelta(days=1)).isoformat()  # Allow immediate grab

    user.investments = investments
    flag_modified(user, "investments")

    # Referral bonus — only if referrer has an approved investment
    referral_bonus = 0.0
    if user.referral_code:
        referrer = db.query(UserDB).filter_by(username=user.referral_code).first()
        if referrer:
            db.refresh(referrer)
            has_approved = any(
                i.get("status") == "approved" for i in (referrer.investments or {}).values()
            )
            if has_approved:
                referral_bonus = inv["amount"] * (REFERRAL_BONUS_PERCENT / 100)
                referrer.referral_bonus_earned = (referrer.referral_bonus_earned or 0.0) + referral_bonus
                referrer.balance = (referrer.balance or 0.0) + referral_bonus
                db.add(referrer)

    db.commit()

    return {
        "success": True,
        "message": (
            f"✅ {commodity} plan for {data.username} approved. "
            f"Daily bonus: KES {info['daily_bonus']}. "
            f"Referral bonus paid: KES {referral_bonus:.2f}"
        ),
    }


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
            "phone": user.phone if user else "N/A",
            "amount": w.amount,
            "charge": w.charge,
            "net_amount": w.net_amount,
            "payment_method": w.payment_method,
            "account_number": w.account_number,
            "status": w.status,
            "requested_at": w.requested_at.isoformat() if w.requested_at else None,
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
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    if withdrawal.status != "pending":
        raise HTTPException(status_code=400, detail="Withdrawal already processed")

    user = db.query(UserDB).filter_by(id=withdrawal.user_id).first()
    if not user or user.balance < withdrawal.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance or user not found")

    user.balance -= withdrawal.amount
    withdrawal.status = "approved"
    withdrawal.approved_at = datetime.utcnow()
    db.commit()

    return {"success": True, "message": f"Withdrawal #{data.withdrawal_id} approved. KES {withdrawal.net_amount:.2f} to be sent."}


@app.post("/admin/withdraw_reject")
def reject_withdrawal(data: AdminAction = Body(...), db: Session = Depends(get_db)):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    if not data.withdrawal_id:
        raise HTTPException(status_code=400, detail="withdrawal_id is required")

    withdrawal = db.query(WithdrawalRequest).filter_by(id=data.withdrawal_id).first()
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    if withdrawal.status != "pending":
        raise HTTPException(status_code=400, detail="Withdrawal already processed")

    withdrawal.status = "rejected"
    db.commit()
    return {"success": True, "message": f"Withdrawal #{data.withdrawal_id} rejected."}


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
    return {"success": True, "message": f"Password for {data.username} reset to '123456'"}


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
    return {"success": True, "message": f"User {data.username} has been removed"}


# ================================================================
#  HEALTH CHECK
# ================================================================

@app.get("/")
def root():
    return {"status": "ok", "app": "MulaHub Backend", "plans": list(COMMODITY_INFO.keys())}


# ================================================================
#  RUN
# ================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
