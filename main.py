from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

app = FastAPI()

# CORS
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

# In-memory DB
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
    referral: str | None = None
    referred_users: list[str] = []
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
        raise HTTPException(403, "Invalid admin credentials")
    return True

# Registration
@app.post("/register")
def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    referral: str | None = Form(None)
):
    if username in users:
        raise HTTPException(400, "Username already exists")
    if password != confirm:
        raise HTTPException(400, "Passwords do not match")
    if not number.isdigit() or len(number) != 10:
        raise HTTPException(400, "Invalid phone number")
    password_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=password_hash,
        referral=referral
    ).dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    return {"message": "Registration successful. Await admin approval."}

# Login
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"message": "Admin login successful", "is_admin": True}
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    if not u["approved"]:
        raise HTTPException(403, "Account not yet approved by admin")
    return {"message": "Login successful", "is_admin": False}

# Investment
@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u or not u["approved"]:
        raise HTTPException(403, "Account not approved")
    if amount < 500:
        raise HTTPException(400, "Minimum investment is KES 500")
    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=transaction_ref,
        timestamp=datetime.now()
    ).dict()
    return {"message": "Investment submitted. Await admin approval."}

# Admin: Approve user
@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    u["approved"] = True
    return {"message": f"{username} approved successfully"}

# Admin: Approve investment
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
        users[ref]["balance"] += inv["amount"] * 0.05
    return {"message": f"Investment for {username} approved"}

# Bonus Grab
@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment found")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(400, "Bonus already claimed today")
    bonus = inv["amount"] * 0.10
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    return {"message": f"Bonus of KES {bonus:.2f} credited", "bonus": bonus}

# Dashboard
@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return {
        "username": u["username"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat()
    }

# Get user info
@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return {
        "username": u["username"],
        "number": u["number"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat(),
        "approved": u["approved"],
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "total_invested": investments.get(username, {}).get("amount", 0)
    }

# Referrals
@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return u["referred_users"]

# Withdraw (Only Mondays, min 30%)
@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    if datetime.today().weekday() != 0:
        raise HTTPException(400, "Withdrawals allowed only on Mondays")
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment found")
    min_req = 0.3 * inv["amount"]
    if amount < min_req:
        raise HTTPException(400, f"Minimum withdrawal is 30% of investment: KES {min_req:.2f}")
    if u["balance"] < amount:
        raise HTTPException(400, "Insufficient balance")
    u["balance"] -= amount
    return {"message": f"Withdrawal request of KES {amount:.2f} received. Awaiting admin approval."}
