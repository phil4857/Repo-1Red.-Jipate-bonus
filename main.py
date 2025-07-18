from fastapi import FastAPI, Form, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict
import hashlib
import time

app = FastAPI()

users: Dict[str, dict] = {}
investments: Dict[str, dict] = {}
login_attempts: Dict[str, int] = {}

class User(BaseModel):
    username: str
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

@app.get("/")
def root():
    return {"message": "Welcome to Jipate Bonus Investment Platform"}

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), referral: str = Form(None)):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = hash_password(password)
    user = User(username=username, password_hash=password_hash, referral=referral)
    users[username] = user.dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    return {"message": "User registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not users[username]["approved"]:
        raise HTTPException(status_code=403, detail="User not approved yet")
    password_hash = hash_password(password)
    if users[username]["password_hash"] != password_hash:
        login_attempts[username] = login_attempts.get(username, 0) + 1
        if login_attempts[username] >= 3:
            raise HTTPException(status_code=403, detail="Account locked. Contact admin.")
        raise HTTPException(status_code=401, detail="Wrong password")
    login_attempts[username] = 0
    return {"message": f"Login successful for {username}"}

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if not users[username]["approved"]:
        raise HTTPException(status_code=403, detail="User not approved")
    if username in investments:
        raise HTTPException(status_code=400, detail="Duplicate investment already exists")
    if datetime.utcnow().strftime("%A") == "Sunday":
        amount *= 0.95
    investment = Investment(
        username=username,
        amount=amount,
        transaction_ref=transaction_ref,
        timestamp=datetime.utcnow()
    )
    investments[username] = investment.dict()
    return {
        "message": f"Investment submitted for {username}. Awaiting admin approval.",
        "note": "Send payment to MPESA number 0737734533"
    }

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[username]["approved"] = True
    return {"message": f"{username} approved"}

@app.post("/admin/reset_password")
def reset_password(username: str = Form(...), new_password: str = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[username]["password_hash"] = hash_password(new_password)
    login_attempts[username] = 0
    return {"message": "Password reset"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...)):
    if username not in investments:
        raise HTTPException(status_code=404, detail="No investment found")
    if investments[username]["approved"]:
        return {"message": "Already approved"}
    investments[username]["approved"] = True
    amount = investments[username]["amount"]
    users[username]["balance"] += amount
    referrer = users[username].get("referral")
    if referrer and referrer in users:
        users[referrer]["balance"] += amount * 0.05
    return {"message": f"Investment approved for {username}"}

@app.post("/earnings/daily")
def daily_earnings():
    count = 0
    now = time.time()
    for username, inv in investments.items():
        if inv["approved"] and now - users[username]["last_earning_time"] >= 86400:
            earning = inv["amount"] * 0.10
            users[username]["earnings"] += earning
            users[username]["balance"] += earning
            users[username]["last_earning_time"] = now
            count += 1
    return {"message": f"Daily earnings added for {count} users"}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[username]["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    users[username]["balance"] -= amount
    return {"message": f"{amount} withdrawn by {username}. Await confirmation via MPESA."}

@app.get("/admin/view_users")
def view_users():
    return users

@app.get("/admin/view_investments")
def view_investments():
    return investments
