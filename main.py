from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt
import time

app = FastAPI()

# Allow CORS
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

# In-memory storage
users = {}
investments = {}

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"

# Models
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: str = None
    referred_users: list = []
    balance: float = 0.0
    earnings: float = 0.0
    last_earning_time: float = time.time()

class Investment(BaseModel):
    username: str
    amount: float
    transaction_ref: str
    approved: bool = False
    timestamp: datetime

# Utilities
def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

def admin_auth(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    return True

# --- ROUTES ---

@app.post("/register")
def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    referral: str = Form(None)
):
    if username in users:
        raise HTTPException(400, "Username already exists")
    password_hash = hash_pwd(password)

    users[username] = {
        "username": username,
        "number": number,
        "password_hash": password_hash,
        "approved": False,
        "referral": referral,
        "referred_users": [],
        "balance": 0.0,
        "earnings": 0.0,
        "last_earning_time": time.time()
    }

    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    return {"message": f"User {username} registered successfully. Awaiting admin approval."}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"message": "Admin logged in", "admin": True}

    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(400, "Invalid username or password")

    if not u["approved"]:
        raise HTTPException(403, "User not yet approved by admin")

    return {"message": f"Welcome {username}", "admin": False}

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    if username not in users:
        raise HTTPException(404, "User not found")

    if amount < 500:
        raise HTTPException(400, "Minimum investment is KES 500")

    investments[username] = {
        "username": username,
        "amount": amount,
        "transaction_ref": transaction_ref,
        "approved": False,
        "timestamp": datetime.now()
    }

    return {"message": "Investment submitted. Awaiting admin approval."}

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    u["approved"] = True
    return {"message": f"{username} approved successfully"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...), _: bool = Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(404, "Investment not found")
    if inv["approved"]:
        return {"message": "Investment already approved"}

    inv["approved"] = True
    users[username]["balance"] += inv["amount"]

    ref = users[username].get("referral")
    if ref in users:
        users[ref]["balance"] += inv["amount"] * 0.05  # 5% referral bonus

    return {"message": f"Investment for {username} approved"}

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")

    inv = investments.get(username)
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment found. You must invest first.")

    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(400, "Bonus already claimed today")

    daily_bonus = inv["amount"] * 0.10
    u["balance"] += daily_bonus
    u["earnings"] += daily_bonus
    u["last_earning_time"] = now

    return {
        "message": f"Bonus of KES {daily_bonus:.2f} claimed successfully",
        "bonus": daily_bonus,
        "balance": u["balance"],
        "link": "/dashboard.html"
    }

@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return {
        "username": username,
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat()
    }

@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return {
        "username": username,
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat(),
        "is_admin": username == ADMIN_USERNAME,
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

    if datetime.today().weekday() != 0:
        raise HTTPException(400, "Withdrawals allowed only on Mondays")

    inv = investments.get(username)
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment found")

    min_required = 0.3 * inv["amount"]
    if amount < min_required:
        raise HTTPException(400, f"Minimum withdrawal is 30% of investment: {min_required}")

    if u["balance"] < amount:
        raise HTTPException(400, "Insufficient balance")

    u["balance"] -= amount
    return {"message": f"Withdrawal request of KES {amount:.2f} received"}
