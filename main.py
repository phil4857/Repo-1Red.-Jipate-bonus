from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Optional, Dict
import uvicorn

app = FastAPI()

# CORS config to allow frontend (Vercel)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://jipate-bonus-v1-bcti.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory data storage (use DB for production)
users_db: Dict[str, dict] = {}
investments_db: Dict[str, dict] = {}
withdrawals_db: Dict[str, dict] = {}

# 🔐 Preload admin user with known password (admin123)
admin_password = "admin123"
users_db["admin"] = {
    "username": "admin",
    "password_hash": pwd_context.hash(admin_password),
    "approved": True,
    "referral": None,
    "balance": 0,
    "number": "0000000000",  # placeholder
}

# Models
class User(BaseModel):
    username: str
    password: str
    number: str
    referral: Optional[str] = None

class Login(BaseModel):
    username: str
    password: str

# Register endpoint
@app.post("/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    number: str = Form(...),
    referral: Optional[str] = Form(None),
):
    if username in users_db:
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_pw = pwd_context.hash(password)
    users_db[username] = {
        "username": username,
        "password_hash": hashed_pw,
        "approved": True,
        "referral": referral,
        "balance": 0,
        "number": number,
    }
    return {"message": "User registered successfully"}

# Login endpoint
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = users_db.get(username)
    if not user or not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": f"Welcome, {username}!"}

# View users (admin only)
@app.get("/admin/view_users")
def view_users():
    return users_db

# View investments
@app.get("/admin/view_investments")
def view_investments():
    return investments_db

# Invest endpoint
@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...)):
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    investments_db[username] = {"amount": amount}
    users_db[username]["balance"] += amount
    return {"message": "Investment successful"}

# Withdraw endpoint
@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    invested = investments_db.get(username, {}).get("amount", 0)
    balance = users_db[username]["balance"]

    # Calculate limits
    if invested >= 1500:
        max_withdraw = int(invested * 0.3)
    elif invested >= 1000:
        max_withdraw = 300
    elif invested >= 500:
        max_withdraw = 150
    else:
        max_withdraw = 0

    if amount > max_withdraw:
        raise HTTPException(status_code=400, detail=f"Limit is KES {max_withdraw}")
    if amount > balance:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    users_db[username]["balance"] -= amount
    withdrawals_db.setdefault(username, []).append(amount)
    return {"message": "Withdrawal request submitted"}

# Root check
@app.get("/")
def root():
    return {"message": "Jipate Bonus API"}
