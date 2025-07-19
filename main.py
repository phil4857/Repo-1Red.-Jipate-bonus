from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Dict

app = FastAPI()

# CORS for Vercel frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://jipate-bonus-v1-bcti.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory stores
users: Dict[str, dict] = {}
investments: Dict[str, dict] = {}
withdrawals: Dict[str, list] = {}

class User(BaseModel):
    username: str
    password_hash: str
    approved: bool = False
    referral: str = None
    balance: float = 0.0

class Investment(BaseModel):
    username: str
    amount: float

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), referral: str = Form(None)):
    if username in users:
        raise HTTPException(status_code=400, detail="User already exists")
    password_hash = pwd_context.hash(password)
    users[username] = User(
        username=username,
        password_hash=password_hash,
        approved=True,
        referral=referral
    ).dict()
    return {"message": "User registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not pwd_context.verify(password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Login successful", "user": username}

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if username in investments:
        raise HTTPException(status_code=400, detail="Already invested")
    investments[username] = {"username": username, "amount": amount}
    users[username]['balance'] += amount * 0.3  # 30% daily earnings for demo
    return {"message": "Investment successful"}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[username]['balance'] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    users[username]['balance'] -= amount
    withdrawals.setdefault(username, []).append(amount)
    return {"message": "Withdrawal successful, will be processed"}

# Admin endpoints
@app.get("/admin/view_users")
def view_users():
    return users

@app.get("/admin/view_investments")
def view_investments():
    return investments

# Create default admin
admin_password = pwd_context.hash("Admin12345!")
users["admin"] = User(username="admin", password_hash=admin_password, approved=True).dict()
