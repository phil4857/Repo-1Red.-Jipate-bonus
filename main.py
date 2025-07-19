from fastapi import FastAPI, HTTPException, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Dict
import time

app = FastAPI()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://jipate-bonus-v1-bcti.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (use a database in production)
users: Dict[str, Dict] = {}
investments: Dict[str, Dict] = {}
withdrawals: Dict[str, list] = {}
failed_attempts: Dict[str, Dict[str, int]] = {}

# Models
class RegisterForm(BaseModel):
    username: str
    password: str

# Helpers
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def block_login(username: str) -> bool:
    attempt = failed_attempts.get(username, {"count": 0, "last_try": 0})
    if attempt["count"] >= 3 and time.time() - attempt["last_try"] < 3600:
        return True
    return False

def record_failed_attempt(username: str):
    now = time.time()
    attempt = failed_attempts.get(username, {"count": 0, "last_try": now})
    if now - attempt["last_try"] > 3600:
        attempt = {"count": 1, "last_try": now}
    else:
        attempt["count"] += 1
        attempt["last_try"] = now
    failed_attempts[username] = attempt

def reset_failed_attempts(username: str):
    if username in failed_attempts:
        del failed_attempts[username]

# Routes
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    if username in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[username] = {
        "password": hash_password(password),
        "balance": 0,
        "referral": None,
        "joined": time.time(),
    }
    return {"message": "User registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if block_login(username):
        raise HTTPException(status_code=403, detail="Too many failed attempts. Try again later.")
    user = users.get(username)
    if not user or not verify_password(password, user["password"]):
        record_failed_attempt(username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    reset_failed_attempts(username)
    return {"message": "Login successful"}

@app.get("/admin/view_users")
def view_users(username: str = ""):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Unauthorized")
    return users

@app.get("/admin/view_investments")
def view_investments(username: str = ""):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Unauthorized")
    return investments

@app.post("/invest")
def invest(username: str = Form(...), amount: int = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if username not in investments:
        investments[username] = {"amount": 0, "timestamp": time.time()}
    investments[username]["amount"] += amount
    users[username]["balance"] += amount
    return {"message": f"Invested KES {amount} successfully"}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: int = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[username]["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    users[username]["balance"] -= amount
    withdrawals.setdefault(username, []).append({
        "amount": amount,
        "timestamp": time.time()
    })
    return {"message": "Withdrawal successful"}

@app.get("/")
def home():
    return {"message": "Welcome to Jipate Bonus!"}
