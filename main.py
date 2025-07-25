from fastapi import FastAPI, Form, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import bcrypt
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {}
investments = {}
withdrawals = {}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"
ADMIN_TOKEN = "admin_static_token"
INVESTMENT_NUMBER = "0737734533"  # ✅ Centralized number

class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: str | None = None
    referred_users: list[str] = []
    balance: float = 0.0
    earnings: float = 0.0
    last_earning_time: float = 0.0
    bonus_days_remaining: int = 0

class Investment(BaseModel):
    username: str
    amount: float
    transaction_ref: str
    approved: bool = False
    timestamp: datetime

class WithdrawalRequest(BaseModel):
    username: str
    amount: float
    approved: bool = False
    timestamp: datetime

def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

def admin_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ")[1]
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token")
    return True

@app.post("/register")
def register(username: str = Form(...), number: str = Form(...), password: str = Form(...), referral: str | None = Form(None)):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=password_hash,
        referral=referral
    ).dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    return {"message": f"User {username} registered successfully. Awaiting admin approval."}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"message": "Admin login successful", "is_admin": True, "is_approved": True}
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not yet approved by admin")
    return {
        "message": f"Login successful. Welcome {username}",
        "is_admin": False,
        "is_approved": True
    }

@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    bonus_available = False
    bonus_message = "No approved investment yet"
    if inv and inv.get("approved", False):
        now = time.time()
        if u["bonus_days_remaining"] > 0 and now - u["last_earning_time"] >= 86400:
            bonus_available = True
            bonus_message = "Bonus available to grab"
        else:
            bonus_message = "Bonus already claimed today or period ended"

    return {
        "username": u["username"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "approved": u["approved"],
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "bonus_available": bonus_available,
        "bonus_message": bonus_message,
        "bonus_days_remaining": u["bonus_days_remaining"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat() if u["last_earning_time"] else None,
        "investment_amount": inv["amount"] if inv else 0,
        "investment_number": INVESTMENT_NUMBER  # ✅ Added
    }

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u or not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not approved")
    if amount < 500:
        raise HTTPException(status_code=400, detail="Minimum investment is KES 500")
    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=transaction_ref,
        timestamp=datetime.now()
    ).dict()
    return {
        "message": "Investment submitted. Await admin approval.",
        "investment_number": INVESTMENT_NUMBER  # ✅ Added
    }

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv or not inv.get("approved", False):
        raise HTTPException(status_code=400, detail="No approved investment found")

    if u["bonus_days_remaining"] <= 0:
        raise HTTPException(status_code=400, detail="No bonus period left")

    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(status_code=400, detail="Bonus already claimed today")

    bonus = inv["amount"] * 0.10
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] -= 1

    return {
        "message": f"Bonus of KES {bonus:.2f} credited",
        "bonus": bonus,
        "balance": u["balance"],
        "days_remaining": u["bonus_days_remaining"]
    }

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if datetime.today().weekday() != 0:
        raise HTTPException(status_code=400, detail="Withdrawals allowed only on Mondays")
    if not inv or not inv.get("approved", False):
        raise HTTPException(status_code=400, detail="No approved investment found")
    min_req = 0.3 * inv["amount"]
    if amount < min_req:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal is 30% of investment: KES {min_req:.2f}")
    if u["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    withdrawals[username] = WithdrawalRequest(
        username=username,
        amount=amount,
        timestamp=datetime.now()
    ).dict()
    return {"message": f"Withdrawal of KES {amount:.2f} requested. Awaiting admin approval."}

# -------------------- ADMIN ROUTES --------------------

@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"message": "Admin login successful", "token": ADMIN_TOKEN}
    raise HTTPException(status_code=403, detail="Invalid admin credentials")

@app.get("/admin/users")
def get_all_users(_: bool = Depends(admin_auth)):
    result = []
    for uname, u in users.items():
        inv = investments.get(uname)
        result.append({
            "username": u["username"],
            "number": u["number"],
            "approved": u["approved"],
            "balance": u["balance"],
            "earnings": u["earnings"],
            "referral": u["referral"],
            "referred_users": u["referred_users"],
            "total_invested": inv["amount"] if inv else 0,
            "investment_approved": inv["approved"] if inv else False,
            "investment_number": INVESTMENT_NUMBER  # ✅ Added
        })
    return result

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["approved"] = True
    return {"message": f"User {username} approved"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...), _: bool = Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(status_code=404, detail="Investment not found")
    if inv["approved"]:
        return {"message": "Already approved"}
    inv["approved"] = True
    u = users[username]
    u["balance"] += inv["amount"]

    # Set bonus period
    amt = inv["amount"]
    if amt < 1000:
        u["bonus_days_remaining"] = 30
    elif amt < 3000:
        u["bonus_days_remaining"] = 60
    else:
        u["bonus_days_remaining"] = 90

    # Referral bonus
    ref = u.get("referral")
    if ref and ref in users:
        users[ref]["balance"] += amt * 0.05

    return {"message": f"Investment for {username} approved"}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    if w["approved"]:
        return {"message": "Already approved"}
    w["approved"] = True
    return {"message": f"Withdrawal of {w['amount']} approved"}

@app.post("/admin/reset-password")
def reset_password(target_username: str = Form(...), new_password: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(target_username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"Password for {target_username} reset"}
