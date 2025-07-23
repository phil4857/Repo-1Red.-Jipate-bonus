from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Use "*" for now to avoid CORS issues
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {}
investments = {}
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"

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

# Helper functions
def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

def admin_auth(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    return True

# ✅ Register
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), number: str = Form(...), referral: str = Form(None)):
    if username in users:
        raise HTTPException(400, "Username already exists")
    pwd_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=pwd_hash,
        referral=referral,
        referred_users=[]
    ).dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    return {"message": "Registration successful, pending admin approval."}

# ✅ Login
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    return {"message": "Login successful", "approved": u["approved"]}

# ✅ Invest
@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    if amount < 500:
        raise HTTPException(400, "Minimum investment is KES 500")
    investments[username] = {
        "username": username,
        "amount": amount,
        "transaction_ref": transaction_ref,
        "approved": False,
        "timestamp": datetime.now()
    }
    return {"message": "Investment submitted, pending admin approval"}

# ✅ Grab Bonus
@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    if not u or not u["approved"]:
        raise HTTPException(403, "User not approved")
    inv = investments.get(username)
    if not inv or not inv["approved"]:
        raise HTTPException(403, "No approved investment found")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(400, "Bonus already claimed today")
    daily_bonus = inv["amount"] * 0.10
    u["balance"] += daily_bonus
    u["earnings"] += daily_bonus
    u["last_earning_time"] = now
    return {
        "message": f"Bonus of KES {daily_bonus:.2f} claimed",
        "bonus": daily_bonus,
        "balance": u["balance"]
    }

# ✅ Admin Approves User
@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    u["approved"] = True
    return {"message": f"{username} approved"}

# ✅ Admin Approves Investment
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

# ✅ Dashboard
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

# ✅ Referrals
@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return u["referred_users"]

# ✅ User Info
@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    return {
        "username": username,
        "balance": u["balance"],
        "earnings": u["earnings"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat(),
        "is_admin": username == ADMIN_USERNAME,
        "total_invested": investments.get(username, {}).get("amount", 0)
    }

# ✅ Withdraw
@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(404, "User not found")
    if datetime.today().weekday() != 0:
        raise HTTPException(400, "Withdrawals allowed only on Mondays")
    inv = investments.get(username)
    if not inv or not inv["approved"]:
        raise HTTPException(400, "No approved investment")
    min_required = 0.3 * inv["amount"]
    if amount < min_required:
        raise HTTPException(400, f"Minimum withdrawal is 30% of investment: {min_required}")
    if u["balance"] < amount:
        raise HTTPException(400, "Insufficient balance")
    u["balance"] -= amount
    return {"message": f"Withdrawal request for KES {amount:.2f} received"}
