import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
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

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.warning("DATABASE_URL not set; using fallback for local testing")
    DATABASE_URL = "sqlite:///./test.db"  # fallback for local dev only

SECRET_KEY = os.getenv("SECRET_KEY", "replace-me-with-secure-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")  # comma-separated or "*"
if ALLOWED_ORIGINS == "*":
    origins = ["*"]
else:
    origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]

MPESA_NUMBER = os.getenv("MPESA_NUMBER", "0752964507")
REFERRAL_BONUS_PERCENT = float(os.getenv("REFERRAL_BONUS_PERCENT", "10"))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "PHIL4857")

# Commodity config (could be moved to env/config file)
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

# ---------------- App & DB (deferred init) ----------------

app = FastAPI(title="Mkoba Wallet Backend (refactored)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base = declarative_base()
engine = None
SessionLocal = None


def init_db():
    global engine, SessionLocal
    if engine is None:
        engine = create_engine(DATABASE_URL, pool_pre_ping=True)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        # In simple setups this will create tables. For production use Alembic migrations.
        Base.metadata.create_all(bind=engine)
        logger.info("Database engine initialized")


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as e:
        logger.exception("Failed to initialize DB on startup: %s", e)
        # Do not re-raise here to allow the process to start; handle runtime DB errors gracefully.


@app.on_event("shutdown")
def on_shutdown():
    # SQLAlchemy engine disposal
    try:
        if engine is not None:
            engine.dispose()
    except Exception:
        pass


def get_db():
    if SessionLocal is None:
        raise RuntimeError("DB not initialized")
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# Dependency to get current user from Authorization header
from fastapi.security import OAuth2PasswordBearer

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


@app.get("/health", tags=["root"])
def health():
    return {"status": "ok"}


@app.post("/register", response_model=dict, status_code=201, tags=["auth"])
def register(payload: UserCreate = Body(...), db: Session = Depends(get_db)):
    username = payload.username
    phone = payload.phone
    password = payload.password
    referral = payload.referral.strip().lower() if payload.referral else None

    # check existing user
    existing = db.query(UserDB).filter(UserDB.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_pwd(password)
    new_user = UserDB(
        username=username,
        phone=phone,
        password_hash=hashed_pw,
        referral_code=referral,
        approved=False  # admin must approve
    )
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except SQLAlchemyError as e:
        db.rollback()
        logger.exception("DB error registering user: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create user")

    referral_link = f"https://mkobawallets.vercel.app/register.html?ref={username}"
    return {"message": "User registered successfully. Awaiting admin approval.", "referral_link": referral_link}


@app.post("/login", response_model=Token, tags=["auth"])
def login(payload: UserLogin = Body(...), db: Session = Depends(get_db)):
    username = payload.username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not check_pwd(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid password")

    if not user.approved:
        raise HTTPException(status_code=403, detail="Account not approved")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/dashboard", response_model=DashboardResponse, tags=["user"])
def dashboard(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    user = current_user

    investments = user.investments or {}
    now = datetime.utcnow()
    investments_status = {}
    daily_earnings = 0.0

    # iterate investments and credit earnings if needed
    # NOTE: to avoid race conditions consider a background job in production
    for commodity, inv in list(investments.items()):
        try:
            expiry = datetime.fromisoformat(inv["expiry_date"])
            start = datetime.fromisoformat(inv["start_date"])
            last_credited = datetime.fromisoformat(inv.get("last_credited", start.isoformat()))
        except Exception:
            # If malformed data, skip
            continue

        if now >= expiry:
            # optionally remove expired investments or keep for history
            continue

        days_total = COMMODITY_INFO.get(commodity, {}).get("expiry_days", 1)
        if days_total <= 0:
            continue

        daily_rate = inv["amount"] / days_total

        # compute full days since last credit
        days_to_credit = (now - last_credited).days
        if days_to_credit > 0:
            credit = daily_rate * days_to_credit
            user.balance = (user.balance or 0.0) + credit
            user.earnings = (user.earnings or 0.0) + credit
            inv["last_credited"] = now.isoformat()

        investments_status[commodity] = {
            "amount": inv.get("amount", 0.0),
            "days_remaining": max((expiry - now).days, 0),
            "daily_earning": daily_rate
        }
        daily_earnings += daily_rate

    # persist any modified investments / balances
    try:
        user.investments = investments
        db.add(user)
        db.commit()
        db.refresh(user)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to update user during dashboard processing")

    return DashboardResponse(
        username=user.username,
        balance=user.balance or 0.0,
        earnings=user.earnings or 0.0,
        investments=investments_status,
        daily_earnings=daily_earnings,
        approved=user.approved,
        referral_link=f"https://mkobawallets.vercel.app/register.html?ref={user.username}",
        referral_bonus_earned=user.referral_bonus_earned or 0.0,
    )


@app.post("/invest/request", response_model=dict, tags=["invest"])
def invest_request(payload: InvestRequest = Body(...)):
    commodity = payload.commodity.strip().lower()
    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")
    price = COMMODITY_INFO[commodity]["price"]
    return {"message": "Send payment to M-Pesa", "price": price, "mpesa_number": MPESA_NUMBER}


@app.post("/invest/confirm", response_model=dict, tags=["invest"])
def invest_confirm(payload: InvestRequest = Body(...),
                   db: Session = Depends(get_db),
                   current_user: UserDB = Depends(get_current_user)):
    commodity = payload.commodity.strip().lower()
    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail="Invalid commodity")

    price = COMMODITY_INFO[commodity]["price"]
    user = current_user

    investments = dict(user.investments or {})

    if commodity in investments:
        raise HTTPException(status_code=400, detail="Already invested in this commodity")

    now = datetime.utcnow()
    investments[commodity] = {
        "amount": price,
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])).isoformat(),
        "last_credited": now.isoformat()
    }

    user.investments = investments

    # award referral bonus to referrer if present
    if user.referral_code:
        referrer = db.query(UserDB).filter(UserDB.username == user.referral_code).first()
        if referrer:
            bonus = price * (REFERRAL_BONUS_PERCENT / 100.0)
            referrer.earnings = (referrer.earnings or 0.0) + bonus
            referrer.referral_bonus_earned = (referrer.referral_bonus_earned or 0.0) + bonus
            db.add(referrer)

    try:
        db.add(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to confirm investment")
        raise HTTPException(status_code=500, detail="Failed to confirm investment")

    return {"message": f"Investment in {commodity} confirmed"}


@app.post("/withdraw/request", response_model=dict, tags=["withdraw"])
def withdraw_request(payload: WithdrawRequestSchema = Body(...),
                     db: Session = Depends(get_db),
                     current_user: UserDB = Depends(get_current_user)):
    amount = payload.amount
    user = current_user

    if amount < 500:
        raise HTTPException(status_code=400, detail="Minimum withdrawal is KES 500")

    if (user.balance or 0.0) < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    req = WithdrawalRequest(user_id=user.id, amount=amount)
    try:
        db.add(req)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to create withdrawal request")
        raise HTTPException(status_code=500, detail="Failed to submit withdrawal")

    logger.info("Withdrawal requested: %s KES %s", user.username, amount)
    return {"message": "Withdrawal request submitted"}


# ---------------- Admin endpoints (simple) ----------------

@app.post("/admin/approve", response_model=dict, tags=["admin"])
def admin_approve(username: str = Body(...), admin_password: str = Body(...), db: Session = Depends(get_db)):
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    user = db.query(UserDB).filter(UserDB.username == username.strip().lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.approved = True
    try:
        db.add(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to approve user")
    return {"message": f"User {user.username} approved"}


# ---------------- Token URL for OAuth2PasswordBearer ----------------
# The OAuth2PasswordBearer expects a token URL; provide a route that returns token
@app.post("/token", response_model=Token, tags=["auth"])
def token_for_oauth2(payload: UserLogin = Body(...), db: Session = Depends(get_db)):
    # This duplicates /login behavior but is needed for OAuth2PasswordBearer flows
    username = payload.username.strip().lower()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user or not check_pwd(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.approved:
        raise HTTPException(status_code=403, detail="Account not approved")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
