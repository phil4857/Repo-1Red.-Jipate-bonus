from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt

app = FastAPI()

# CORS settings for frontend hosted on Vercel
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://jipate-bonus-v1-bcti.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simulated database
users = {
    "admin": {
        "username": "admin",
        "password_hash": bcrypt.hashpw("adminpass".encode(), bcrypt.gensalt()).decode(),
        "approved": True,
        "balance": 0,
        "referral": None,
        "phone": "0700000000"
    }
}

investments = {}

# User registration
@app.post("/register")
def register_user(
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    phone: str = Form(...),
    referral: str = Form(None)
):
    if username in users:
        raise HTTPException(status_code=400, detail="User already exists.")
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {
        "username": username,
        "password_hash": hashed,
        "approved": False,
        "referral": referral,
        "balance": 0,
        "phone": phone
    }
    return {"message": "User registered successfully. Awaiting approval."}

# User login
@app.post("/login")
def login_user(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Incorrect password.")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not approved.")
    return {"message": "Login successful."}

# Admin - view all users
@app.get("/admin/view_users")
def view_users():
    return users

# Investment
@app.post("/invest")
def invest(username: str = Form(...), amount: int = Form(...)):
    if username not in users or not users[username]["approved"]:
        raise HTTPException(status_code=400, detail="User not found or not approved.")
    investments[username] = {"amount": amount}
    users[username]["balance"] += amount * 2  # simulate earnings
    return {"message": "Investment recorded."}

# Withdraw
@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: int = Form(...)):
    user = users.get(username)
    if not user or username not in investments:
        raise HTTPException(status_code=400, detail="Account or investment not found.")
    invested = investments[username]["amount"]
    if invested < 500:
        raise HTTPException(status_code=400, detail="Minimum investment is 500.")

    if invested >= 1500:
        max_limit = int(invested * 0.3)
    elif invested >= 1000:
        max_limit = 300
    else:
        max_limit = 150

    if amount > max_limit:
        raise HTTPException(status_code=400, detail=f"Your withdrawal limit is {max_limit}")

    if amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Insufficient balance.")
    
    user["balance"] -= amount
    return {"message": "Withdrawal request received."}
