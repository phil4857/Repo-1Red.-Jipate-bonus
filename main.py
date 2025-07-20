from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

# ====== APP CONFIG ======
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

# ====== DUMMY DATABASE ======
users = {}
investments = {}
login_attempts = {}

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"  # Secure admin password


# ====== MODELS ======
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


# ====== UTILS ======
def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())


def admin_auth(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    return True


# ====== ROUTES ======
@app.get("/")
def root():
    return {"message": "Welcome to Jipate Bonus Investment Platform"}


@app.post("/register")
def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    referral: str = Form(None)
):
    if username in users:
        raise HTTPException(400, "Username already exists")
    if password != confirm:
        raise HTTPException(400, "Passwords do not match")
    if not number.isdigit() or len(number) < 10:
        raise HTTPException(400, "Enter a valid number")
    
    h = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=h,
        referral=referral
    ).dict()
    
    if referral in users:
        users[referral]["referred_users"].append(username)

    return {"message": "User registered successfully"}


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        login_attempts[username] = login_attempts.get(username, 0) + 1
        if login_attempts[username] >= 3:
            raise HTTPException(403, "Account locked. Contact admin.")
        raise HTTPException(401, "Wrong username or password")
    
    if not u["approved"]:
        raise HTTPException(403, "Account not yet approved by admin")

    login_attempts[username] = 0
    return {"message": f"Welcome {username}"}


@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    if not u["approved"]:
        raise HTTPException(403, "User not yet approved")
    if username in investments:
        raise HTTPException(400, "User has already invested")

    adjusted_amount = amount * (0.95 if datetime.utcnow().strftime("%A") == "Sunday" else 1.0)
    investments[username] = Investment(
        username=username,
        amount=adjusted_amount,
        transaction_ref=transaction_ref,
        timestamp=datetime.utcnow()
    ).dict()

    return {"message": f"Investment of KES {adjusted_amount:.2f} submitted. Send payment to 0737734533"}


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


@app.post("/earnings/daily")
def daily():
    now = time.time()
    count = 0
    for u, inv in investments.items():
        if inv["approved"] and now - users[u]["last_earning_time"] >= 86400:
            daily_earning = inv["amount"] * 0.10
            users[u]["balance"] += daily_earning
            users[u]["earnings"] += daily_earning
            users[u]["last_earning_time"] = now
            count += 1
    return {"message": f"Earnings credited for {count} users"}


@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv:
        raise HTTPException(404, "User or investment not found")

    invested = inv["amount"]
    balance = u["balance"]

    limit = 150 if invested < 1000 else (300 if invested < 1500 else invested * 0.3)

    if amount > limit:
        raise HTTPException(400, f"Withdrawal limit is {limit}")
    if amount > balance:
        raise HTTPException(400, "Insufficient balance")

    u["balance"] -= amount
    return {"message": f"Withdrawal request of KES {amount:.2f} submitted for processing"}


@app.get("/admin/view_users")
def view_users(_: bool = Depends(admin_auth)):
    return users


@app.get("/admin/view_investments")
def view_investments(_: bool = Depends(admin_auth)):
    return investments
