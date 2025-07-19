from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from passlib.hash import bcrypt
import uuid

app = FastAPI()

# Allow CORS from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://jipate-bonus-v1-bcti.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory databases
users_db = {}
investments_db = {}

# Admin user setup
admin_username = "admin"
admin_password = "admin123"  # Change this securely
users_db[admin_username] = {
    "username": admin_username,
    "password_hash": bcrypt.hash(admin_password),
    "number": None,
    "balance": 0,
    "referral": None,
    "approved": True
}

# Dependency to get user
def get_user(username: str):
    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/register")
def register_user(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    referral: Optional[str] = Form(None)
):
    if username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    users_db[username] = {
        "username": username,
        "number": number,
        "password_hash": bcrypt.hash(password),
        "referral": referral,
        "balance": 0,
        "approved": True
    }

    return {"message": "User registered successfully"}


@app.post("/login")
def login_user(username: str = Form(...), password: str = Form(...)):
    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Login successful"}


@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...)):
    user = get_user(username)
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")

    investments_db[username] = {
        "amount": amount
    }
    user["balance"] += amount * 2  # e.g. double investment

    return {"message": f"Investment of {amount} successful"}


@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    user = get_user(username)
    investment = investments_db.get(username)

    if not investment:
        raise HTTPException(status_code=400, detail="No investment found")

    invested = investment["amount"]
    balance = user["balance"]

    limit = 0
    if invested >= 500 and invested < 1000:
        limit = 150
    elif invested >= 1000 and invested < 1500:
        limit = 300
    elif invested >= 1500:
        limit = int(invested * 0.3)

    if amount > balance:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    if amount > limit:
        raise HTTPException(status_code=400, detail=f"Withdrawal limit is KES {limit}")

    user["balance"] -= amount

    return {"message": f"Withdrawal of {amount} successful"}


@app.get("/admin/view_users")
def admin_view_users(username: str = "", password: str = ""):
    if username != admin_username or not bcrypt.verify(password, users_db[admin_username]["password_hash"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return users_db


@app.get("/admin/view_investments")
def admin_view_investments(username: str = "", password: str = ""):
    if username != admin_username or not bcrypt.verify(password, users_db[admin_username]["password_hash"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return investments_db
