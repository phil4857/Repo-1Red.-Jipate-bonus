# [PREVIOUS IMPORTS AND APP CONFIG — unchanged]
from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://jipate-bonus-v1-bcti.vercel.app",
        "https://repo-1red-jipate-bonus.onrender.com",
        "http://localhost:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {}
investments = {}
login_attempts = {}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"


# [PREVIOUS MODELS & UTILS — unchanged]

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

def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

def admin_auth(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    return True

# [ALL PREVIOUS ROUTES — unchanged]

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
        users[ref]["balance"] += inv["amount"] * 0.05  # Referral bonus

    return {"message": f"Investment for {username} approved"}


# ✅ NEW: Grab Bonus (once per day)
@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(400, "Bonus already claimed today")

    daily_bonus = 0
    inv = investments.get(username)
    if inv and inv["approved"]:
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


# ✅ NEW: User Dashboard Endpoint
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
