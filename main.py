from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Dict
import uvicorn

app = FastAPI()

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your Vercel frontend URL for better security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory "databases"
users: Dict[str, dict] = {}
investments: Dict[str, dict] = {}

# Add default admin
admin_username = "admin"
admin_password = "admin123"
users[admin_username] = {
    "username": admin_username,
    "phone": "",
    "password_hash": pwd_context.hash(admin_password),
    "approved": True,
    "referral": None,
    "balance": 0
}


# Registration
@app.post("/register")
async def register(
    username: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    referral: str = Form(None)
):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    users[username] = {
        "username": username,
        "phone": phone,
        "password_hash": pwd_context.hash(password),
        "referral": referral,
        "approved": False,
        "balance": 0
    }
    return {"message": "User registered successfully. Awaiting admin approval."}


# Login
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="User not approved yet")
    return {"message": "Login successful"}


# Approve user (Admin only)
@app.post("/admin/approve_user")
async def approve_user(admin: str = Form(...), admin_pass: str = Form(...), user_to_approve: str = Form(...)):
    admin_user = users.get(admin)
    if not admin_user or not pwd_context.verify(admin_pass, admin_user["password_hash"]):
        raise HTTPException(status_code=403, detail="Unauthorized")
    if user_to_approve not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[user_to_approve]["approved"] = True
    return {"message": f"{user_to_approve} approved successfully"}


# View users (Admin only)
@app.get("/admin/view_users")
async def view_users(admin: str = Form(...), admin_pass: str = Form(...)):
    if not users.get(admin) or not pwd_context.verify(admin_pass, users[admin]["password_hash"]):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return users


# Withdraw endpoint
@app.post("/withdraw")
async def withdraw(username: str = Form(...), amount: float = Form(...)):
    user = users.get(username)
    investment = investments.get(username)

    if not user or not investment:
        raise HTTPException(status_code=404, detail="User or investment not found")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="User not approved")
    if amount <= 0 or amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")

    invested = investment["amount"]
    max_limit = 0
    if invested >= 500 and invested < 1000:
        max_limit = 150
    elif invested >= 1000 and invested < 1500:
        max_limit = 300
    elif invested >= 1500:
        max_limit = int(invested * 0.3)

    if amount > max_limit:
        raise HTTPException(status_code=400, detail=f"Withdrawal limit exceeded. Limit: {max_limit}")

    user["balance"] -= amount
    return {"message": "Withdrawal successful"}


# Add investment
@app.post("/invest")
async def invest(username: str = Form(...), amount: float = Form(...)):
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid investment amount")
    investments[username] = {"amount": amount}
    users[username]["balance"] += amount
    return {"message": f"Investment of {amount} added"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=10000)
