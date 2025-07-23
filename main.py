from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

app = FastAPI()

# ---- CORS Configuration ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "https://jipate-bonus-v1-bcti.vercel.app",
        "https://repo-1red-jipate-bonus.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- In‑Memory Data Stores ----
users = {}
investments = {}
withdrawals = {}

# ---- Admin Credentials ----
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"

# ---- Models ----
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

# ---- Utilities ----
def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, h: str) -> bool:
    return bcrypt.checkpw(pw.encode(), h.encode())

def admin_auth(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(403, "Invalid admin credentials")
    return True

# ---- Routes ----

@app.post("/register")
def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    referral: str | None = Form(None),
):
    if username in users:
        raise HTTPException(400, "Username already exists")
    if len(password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    pwd_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=pwd_hash,
        referral=referral
    ).dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    return {"message": f"User {username} registered. Await admin approval."}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"message": "Admin logged in", "is_admin": True}
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    if not u["approved"]:
        raise HTTPException(403, "Account not yet approved")
    return {"message": f"Welcome {username}", "is_admin": False}

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    if not u["approved"]:
        raise HTTPException(403, "Account not approved")
    if amount < 500:
        raise HTTPException(400, "Minimum investment is KES 500")
    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=transaction_ref,
        timestamp=datetime.now()
    ).dict()
    return {"message": "Investment submitted. Await admin approval."}

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
    users[username]["balance"] += inv["amount"]
    # referral bonus
    ref = users[username].get("referral")
    if ref in users:
        users[ref]["balance"] += inv["amount"] * 0.05
        users[ref]["earnings"] += inv["amount"] * 0.05
    return {"message": f"Investment for {username} approved"}

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    inv = investments.get(username)
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(400, "Bonus already claimed today")
    bonus = inv["amount"] * 0.10
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    return {
        "message": f"Daily bonus of KES {bonus:.2f} credited",
        "bonus": bonus,
        "balance": u["balance"]
    }

@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return {
        "username": username,
        "number": u["number"],
        "approved": u["approved"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat(),
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "total_invested": investments.get(username, {}).get("amount", 0)
    }

@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return u["referred_users"]

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    # only Mondays
    if datetime.today().weekday() != 0:
        raise HTTPException(400, "Withdrawals only on Mondays")
    inv = investments.get(username)
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment")
    min_req = 0.3 * inv["amount"]
    if amount < min_req:
        raise HTTPException(400, f"Minimum withdrawal is 30%: KES {min_req:.2f}")
    if u["balance"] < amount:
        raise HTTPException(400, "Insufficient balance")
    # queue for admin approval
    withdrawals.setdefault(username, []).append({"amount": amount, "timestamp": datetime.now()})
    return {"message": f"Withdrawal KES {amount:.2f} requested. Await admin approval."}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w_list = withdrawals.get(username, [])
    if not w_list:
        raise HTTPException(404, "No pending withdrawals")
    req = w_list.pop(0)
    users[username]["balance"] -= req["amount"]
    return {"message": f"Processed withdrawal of KES {req['amount']:.2f} for {username}"}
