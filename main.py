from fastapi import FastAPI, Form, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores (replace with DB in production)
users = {}
investments = {}
withdrawals = {}

# Platform config
PLATFORM_NAME = "Mkoba Wallet"
PAYMENT_NUMBER = "0739075065"

# Admin credentials & token
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"
ADMIN_TOKEN = "admin_static_token"

# ---------------- Models ----------------
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

# ---------------- Utilities ----------------
def hash_pwd(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw, h):
    return bcrypt.checkpw(pw.encode(), h.encode())

# Admin auth via Bearer token
def admin_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid token")
    token = authorization.split()[1]
    if token != ADMIN_TOKEN:
        raise HTTPException(403, "Invalid admin token")
    return True

# ---------------- User Routes ----------------
@app.post("/register")
def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    referral: str | None = Form(None)
):
    if username in users:
        raise HTTPException(400, "Username already exists")
    pw_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=pw_hash,
        referral=referral
    ).dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    return {
        "message": f"User {username} registered. Awaiting approval.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    # Admin login
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {
            "message": "Admin login successful",
            "is_admin": True,
            "is_approved": True,
            "token": ADMIN_TOKEN
        }
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    if not u["approved"]:
        raise HTTPException(403, "Account not yet approved")
    return {"message": f"Welcome {username}", "is_admin": False, "is_approved": True}

@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(404, "User not found")

    # Bonus status
    bonus_available = False
    bonus_message = "No approved investment"
    if inv and inv["approved"]:
        now = time.time()
        if u["bonus_days_remaining"] > 0 and now - u["last_earning_time"] >= 86400:
            bonus_available = True
            bonus_message = "Bonus available"
        else:
            bonus_message = "Already claimed or period ended"

    return {
        "username": u["username"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "approved": u["approved"],
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "investment_amount": inv["amount"] if inv else 0,
        "bonus_available": bonus_available,
        "bonus_message": bonus_message,
        "bonus_days_remaining": u["bonus_days_remaining"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat() if u["last_earning_time"] else None,
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u or not u["approved"]:
        raise HTTPException(403, "Account not approved")
    if amount < 500:
        raise HTTPException(400, "Minimum investment is KES 500")
    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=transaction_ref,
        timestamp=datetime.now()
    ).dict()
    return {
        "message": "Investment submitted. Pending approval.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment")
    if u["bonus_days_remaining"] <= 0:
        raise HTTPException(400, "No bonus period left")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(400, "Bonus already claimed today")

    bonus = inv["amount"] * 0.10
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] -= 1

    return {
        "message": f"Bonus KES {bonus:.2f} credited",
        "bonus": bonus,
        "balance": u["balance"],
        "days_remaining": u["bonus_days_remaining"]
    }

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    if datetime.today().weekday() != 0:  # Only on Mondays
        raise HTTPException(400, "Withdrawals only on Mondays")
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment")
    min_req = 0.3 * inv["amount"]
    if amount < min_req:
        raise HTTPException(400, f"Minimum withdrawal is 30%: KES {min_req:.2f}")
    if u["balance"] < amount:
        raise HTTPException(400, "Insufficient balance")

    withdrawals[username] = WithdrawalRequest(
        username=username,
        amount=amount,
        timestamp=datetime.now()
    ).dict()
    return {"message": f"Withdrawal KES {amount:.2f} requested. Pending approval."}

@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return u["referred_users"]

# ---------------- Admin Routes ----------------
@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"message": "Admin login successful", "token": ADMIN_TOKEN}
    raise HTTPException(403, "Invalid admin credentials")

@app.get("/admin/users")
def get_all_users(_: bool = Depends(admin_auth)):
    out = []
    for uname, u in users.items():
        inv = investments.get(uname)
        w = withdrawals.get(uname)
        out.append({
            "username": u["username"],
            "number": u["number"],
            "approved": u["approved"],
            "balance": u["balance"],
            "earnings": u["earnings"],
            "referral": u["referral"],
            "referred_users": u["referred_users"],
            "total_invested": inv["amount"] if inv else 0,
            "investment_approved": inv["approved"] if inv else False,
            "pending_withdrawal": w["amount"] if w and not w["approved"] else 0
        })
    return out

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    u["approved"] = True
    return {"message": f"User {username} approved"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...), _: bool = Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(404, "Investment not found")
    if inv["approved"]:
        return {"message": "Already approved"}

    inv["approved"] = True
    u = users[username]
    amt = inv["amount"]

    # Credit principal
    u["balance"] += amt
    # Set bonus period
    u["bonus_days_remaining"] = 30 if amt < 1000 else 60 if amt < 3000 else 90

    # Referral bonus
    ref = u["referral"]
    if ref in users:
        users[ref]["balance"] += amt * 0.05
        users[ref]["earnings"] += amt * 0.05

    return {"message": f"Investment for {username} approved"}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(404, "Withdrawal not found")
    if w["approved"]:
        return {"message": "Already approved"}

    u = users[username]
    if u["balance"] < w["amount"]:
        raise HTTPException(400, "Insufficient balance to approve withdrawal")

    u["balance"] -= w["amount"]
    w["approved"] = True
    return {"message": f"Withdrawal of KES {w['amount']:.2f} approved"}

@app.post("/admin/reset-password")
def reset_password(target_username: str = Form(...), new_password: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(target_username)
    if not u:
        raise HTTPException(404, "User not found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"Password for {target_username} reset successfully"}
