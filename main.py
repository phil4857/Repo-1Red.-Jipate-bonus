import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import secrets

# ---------------- CONFIG ----------------
DATABASE_URL = "postgresql://mkobawallet_user:HjhGTY2y8VBADx52gGS2Eom3mngX41lt@dpg-d6jesmdm5p6s73dnkda0-a.singapore-postgres.render.com/mkobawallet"
REFERRAL_BONUS_PERCENT = 10  # 10% bonus to referrer
PENDING_INVESTMENTS: Dict[str, Dict[str, Any]] = {}
PENDING_WITHDRAWALS: Dict[str, Dict[str, Any]] = {}

# ---------------- APP SETUP ----------------
app = FastAPI(title="Mkoba Wallet Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    balance = Column(Float, default=10000.0)
    earnings = Column(Float, default=0.0)
    investments = Column(JSON, default={})
    referral = Column(String, default="")
    bonus_days_remaining = Column(Integer, default=0)
    is_admin = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)

security = HTTPBasic()

# ---------------- HELPERS ----------------
def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_pwd(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


def admin_required(credentials: HTTPBasicCredentials = Depends(security)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == credentials.username).first()
    if not user or not user.is_admin or not check_pwd(credentials.password, user.password_hash):
        db.close()
        raise HTTPException(status_code=403, detail="Admin access required")
    db.close()
    return user


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

# ---------------- INITIAL ADMIN ----------------
def create_admin():
    db = SessionLocal()
    admin = db.query(UserDB).filter(UserDB.username == "admin").first()
    if not admin:
        new_admin = UserDB(
            username="admin",
            phone="0000000000",
            password_hash=hash_pwd("PHIL4857"),
            approved=True,
            is_admin=True
        )
        db.add(new_admin)
        db.commit()
        logger.info("Admin account created")
    db.close()


create_admin()

# ---------------- ROUTES ----------------
@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------- REGISTER ----------------
@app.post("/register")
def register(username: str = Form(...), phone: str = Form(...), password: str = Form(...), referral: str = Form("")):
    db = SessionLocal()
    existing_user = db.query(UserDB).filter(UserDB.username == username).first()
    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_pwd(password)
    new_user = UserDB(username=username, phone=phone, password_hash=hashed_pw, referral=referral)
    db.add(new_user)

    # Handle referral bonus
    if referral:
        ref_user = db.query(UserDB).filter(UserDB.username == referral).first()
        if ref_user:
            bonus = new_user.balance * (REFERRAL_BONUS_PERCENT / 100)
            ref_user.balance += bonus
            logger.info(f"Referral bonus: {bonus} added to {ref_user.username}")

    db.commit()
    db.refresh(new_user)
    db.close()

    logger.info(f"User {username} registered successfully")
    return {"message": f"User {username} registered successfully. Pending approval."}


# ---------------- LOGIN ----------------
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")
    if not check_pwd(password, user.password_hash):
        db.close()
        raise HTTPException(status_code=400, detail="Invalid password")
    if not user.approved:
        db.close()
        raise HTTPException(status_code=403, detail="Account not approved")
    db.close()
    return {"message": "Login successful", "username": username, "balance": user.balance, "earnings": user.earnings, "is_admin": user.is_admin}


# ---------------- DASHBOARD ----------------
@app.get("/dashboard")
def dashboard(username: str):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user or not user.approved:
        db.close()
        raise HTTPException(status_code=403, detail="Account not approved")

    investments_status = {}
    for commodity, inv in (user.investments or {}).items():
        start = datetime.fromisoformat(inv["start_date"])
        expiry = datetime.fromisoformat(inv["expiry_date"])
        remaining_days = max((expiry - datetime.utcnow()).days, 0)
        investments_status[commodity] = {"amount": inv["amount"], "days_remaining": remaining_days}

    db.close()
    return {"username": username, "balance": user.balance, "earnings": user.earnings, "investments": investments_status}


# ---------------- INVESTMENT ----------------
@app.post("/invest/request")
def invest_request(username: str = Form(...), commodity: str = Form(...)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user or not user.approved:
        db.close()
        raise HTTPException(status_code=403, detail="Account not approved")
    if commodity not in COMMODITY_INFO:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid commodity")

    price = COMMODITY_INFO[commodity]["price"]
    if user.balance < price:
        db.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")

    PENDING_INVESTMENTS[username] = {"commodity": commodity, "price": price}
    db.close()
    return {"message": f"Investment request for {commodity} created. Pending confirmation."}


@app.post("/invest/confirm")
def invest_confirm(username: str = Form(...)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    pending = PENDING_INVESTMENTS.pop(username, None)
    if not user or not user.approved or not pending:
        db.close()
        raise HTTPException(status_code=400, detail="No pending investment or user not approved")

    commodity = pending["commodity"]
    price = pending["price"]

    if user.balance < price:
        db.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")

    user.balance -= price
    inv_data = {
        "amount": price,
        "start_date": datetime.utcnow().isoformat(),
        "expiry_date": (datetime.utcnow() + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])).isoformat()
    }
    investments = user.investments or {}
    investments[commodity] = inv_data
    user.investments = investments

    db.commit()
    db.refresh(user)
    db.close()
    return {"message": f"Investment in {commodity} confirmed"}


# ---------------- WITHDRAWAL ----------------
@app.post("/withdraw/request")
def withdraw_request(username: str = Form(...), amount: float = Form(...)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user or not user.approved:
        db.close()
        raise HTTPException(status_code=403, detail="Account not approved")

    if datetime.utcnow().weekday() != 0:
        db.close()
        raise HTTPException(status_code=400, detail="Withdrawals allowed only on Monday")
    if amount <= 0 or amount > user.balance:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")

    PENDING_WITHDRAWALS[username] = {"amount": amount}
    db.close()
    return {"message": f"Withdrawal request for KES {amount} created. Pending confirmation."}


@app.post("/withdraw/confirm")
def withdraw_confirm(username: str = Form(...)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    pending = PENDING_WITHDRAWALS.pop(username, None)
    if not user or not user.approved or not pending:
        db.close()
        raise HTTPException(status_code=400, detail="No pending withdrawal or user not approved")

    amount = pending["amount"]
    if user.balance < amount:
        db.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")

    user.balance -= amount
    db.commit()
    db.refresh(user)
    db.close()
    return {"message": f"Withdrawal of KES {amount} successful"}


# ---------------- ADMIN ----------------
@app.get("/admin/users")
def list_users(admin: UserDB = Depends(admin_required)):
    db = SessionLocal()
    users = db.query(UserDB).all()
    result = [
        {"username": u.username, "approved": u.approved, "balance": u.balance, "earnings": u.earnings}
        for u in users
    ]
    db.close()
    return result


@app.post("/admin/approve-user")
def admin_approve_user(username: str = Form(...), admin: UserDB = Depends(admin_required)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")
    user.approved = True
    db.commit()
    db.refresh(user)
    db.close()
    return {"message": f"User {username} approved successfully"}


@app.post("/admin/approve-withdrawal")
def admin_approve_withdrawal(username: str = Form(...), admin: UserDB = Depends(admin_required)):
    db = SessionLocal()
    user = db.query(UserDB).filter(UserDB.username == username).first()
    pending = PENDING_WITHDRAWALS.pop(username, None)
    if not user or not pending:
        db.close()
        raise HTTPException(status_code=400, detail="No pending withdrawal or user not found")
    if user.balance < pending["amount"]:
        db.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")
    user.balance -= pending["amount"]
    db.commit()
    db.refresh(user)
    db.close()
    return {"message": f"Withdrawal of KES {pending['amount']} approved"}
