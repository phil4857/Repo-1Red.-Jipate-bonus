from fastapi import FastAPI, Form, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt
import time

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory data
users = {}
investments = {}
withdrawals = {}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"

# Models
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: str | None = None
    referred_users: list[str] = []
    balance: float = 0.0
    earnings: float = 0.0
    last_earning_time: float = time.time()

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

# Utilities
def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

# 🔐 FIXED: Admin token-based dependency
def admin_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ")[1]
    if token != "admin_static_token":
        raise HTTPException(status_code=403, detail="Invalid admin token")
    return True

# Stub OTP endpoint
@app.post("/send_otp")
def send_otp(number: str = Form(...)):
    return {"message": f"OTP sent to {number}"}

# ---------------- USER ROUTES ----------------

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
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": u["username"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat()
    }

@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    inv = investments.get(username)
    return {
        "username": u["username"],
        "number": u["number"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat(),
        "approved": u["approved"],
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "total_invested": inv["amount"] if inv else 0
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
    return {"message": "Investment submitted. Await admin approval."}

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv or not inv.get("approved", False):
        raise HTTPException(status_code=400, detail="No approved investment found")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(status_code=400, detail="Bonus already claimed today")
    bonus = inv["amount"] * 0.10
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    return {
        "message": f"Bonus of KES {bonus:.2f} credited",
        "bonus": bonus,
        "balance": u["balance"]
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
    return {"message": f"Withdrawal request of KES {amount:.2f} received. Pending admin approval."}

@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u["referred_users"]

# ---------------- ADMIN ROUTES ----------------

@app.post("/admin/login")
async def admin_login(request: Request):
    data = await request.json()
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        return {"token": "admin_static_token"}
    raise HTTPException(status_code=403, detail="Invalid admin credentials")

@app.get("/admin/users")
def get_all_users(_: bool = Depends(admin_auth)):
    return list(users.values())

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["approved"] = True
    return {"message": f"User {username} approved successfully"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...), _: bool = Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(status_code=404, detail="Investment not found")
    if inv["approved"]:
        return {"message": "Investment already approved"}
    inv["approved"] = True
    users[username]["balance"] += inv["amount"]
    ref = users[username].get("referral")
    if ref and ref in users:
        users[ref]["balance"] += inv["amount"] * 0.05
    return {"message": f"Investment for {username} approved"}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal request not found")
    if w["approved"]:
        return {"message": "Withdrawal already approved"}
    w["approved"] = True
    return {"message": f"Withdrawal of KES {w['amount']:.2f} for {username} approved"}

@app.post("/admin/reset-password")
def admin_reset_password(target_username: str = Form(...), new_password: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(target_username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"Password for {target_username} reset successfully"}
