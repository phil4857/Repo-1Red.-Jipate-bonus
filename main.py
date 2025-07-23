from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json, os, bcrypt
from datetime import datetime, timedelta

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_FILE = 'data.json'

# ------------------ Utility Functions ------------------

def load_data():
    if not os.path.exists(DATA_FILE):
        data = {"users": [], "investments": [], "withdrawals": []}
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def find_user(data, username):
    return next((u for u in data["users"] if u["username"] == username), None)

def find_user_by_referral(data, ref_code):
    return next((u for u in data["users"] if u.get("referral_code") == ref_code), None)

def find_investment(data, invest_id):
    return next((i for i in data["investments"] if i["id"] == invest_id), None)

def is_monday():
    return datetime.now().weekday() == 0

# ------------------ Models ------------------

class AuthInput(BaseModel):
    username: str
    password: str

class RegisterInput(AuthInput):
    email: str = ""
    ref: str | None = None

class InvestmentInput(AuthInput):
    amount: float

class WithdrawInput(InvestmentInput): pass

class ApproveUserInput(BaseModel):
    admin_username: str
    admin_password: str
    username: str

class ResetPasswordInput(ApproveUserInput):
    new_password: str

class AdminApproveInput(BaseModel):
    admin_username: str
    admin_password: str
    investment_id: int

# ------------------ Startup ------------------

@app.on_event("startup")
def ensure_admin_exists():
    data = load_data()
    if not any(user.get("is_admin") for user in data["users"]):
        hashed_pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        admin = {
            "username": "admin",
            "password": hashed_pw,
            "email": "",
            "registered_at": datetime.now().isoformat(),
            "is_approved": True,
            "is_admin": True,
            "balance": 0.0,
            "earnings": 0.0,
            "total_invested": 0.0,
            "last_bonus_time": None,
            "referral_code": "",
            "referred_by": None
        }
        data["users"].append(admin)
        save_data(data)
        print("✅ Admin created: username='admin', password='admin123'")

# ------------------ Routes ------------------

@app.post("/register")
def register(payload: RegisterInput):
    data = load_data()
    if find_user(data, payload.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    ref_user = find_user_by_referral(data, payload.ref) if payload.ref else None
    password_hash = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt()).decode()

    new_user = {
        "username": payload.username,
        "password": password_hash,
        "email": payload.email,
        "registered_at": datetime.now().isoformat(),
        "is_approved": False,
        "is_admin": False,
        "balance": 0.0,
        "earnings": 0.0,
        "total_invested": 0.0,
        "last_bonus_time": None,
        "referral_code": os.urandom(6).hex(),
        "referred_by": ref_user["username"] if ref_user else None
    }

    data["users"].append(new_user)
    save_data(data)
    return {"message": "Registration successful. Await admin approval."}

@app.post("/login")
def login(payload: AuthInput):
    data = load_data()
    user = find_user(data, payload.username)
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "message": "Login successful",
        "is_approved": user["is_approved"],
        "is_admin": user["is_admin"]
    }

@app.post("/admin/login")
def admin_login(payload: AuthInput):
    data = load_data()
    user = find_user(data, payload.username)
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Access denied")
    if not bcrypt.checkpw(payload.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Admin login successful", "is_admin": True}

@app.post("/invest")
def create_investment(payload: InvestmentInput):
    data = load_data()
    user = find_user(data, payload.username)
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Authentication failed")
    if not user["is_approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    investment = {
        "id": len(data["investments"]) + 1,
        "user": payload.username,
        "amount": payload.amount,
        "is_approved": False
    }

    data["investments"].append(investment)
    save_data(data)
    return {"message": "Investment submitted. Await admin approval."}

@app.post("/admin/approve_investment")
def approve_investment(payload: AdminApproveInput):
    data = load_data()
    admin = find_user(data, payload.admin_username)
    if not admin or not bcrypt.checkpw(payload.admin_password.encode(), admin["password"].encode()) or not admin.get("is_admin"):
        raise HTTPException(status_code=401, detail="Admin authentication failed")

    investment = find_investment(data, payload.investment_id)
    if not investment:
        raise HTTPException(status_code=404, detail="Investment not found")
    if investment["is_approved"]:
        raise HTTPException(status_code=400, detail="Already approved")

    investment["is_approved"] = True
    user = find_user(data, investment["user"])
    if user:
        user["balance"] += investment["amount"]
        user["total_invested"] += investment["amount"]

        ref = find_user(data, user.get("referred_by"))
        if ref and ref.get("is_approved"):
            ref["balance"] += 50
            ref["earnings"] += 50

    save_data(data)
    return {"message": "Investment approved and credited"}

@app.post("/withdraw")
def withdraw(payload: WithdrawInput):
    data = load_data()
    user = find_user(data, payload.username)
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Authentication failed")
    if not user["is_approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")
    if payload.amount <= 0 or payload.amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Invalid withdrawal amount")
    min_withdraw = 0.3 * user["total_invested"]
    if payload.amount < min_withdraw:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal is {min_withdraw:.2f}")
    if not is_monday():
        raise HTTPException(status_code=400, detail="Withdrawals only allowed on Mondays")

    user["balance"] -= payload.amount
    data["withdrawals"].append({
        "id": len(data["withdrawals"]) + 1,
        "user": payload.username,
        "amount": payload.amount,
        "date": datetime.now().isoformat()
    })
    save_data(data)
    return {"message": f"Withdrawal of {payload.amount:.2f} processed"}

@app.post("/daily_bonus")
def daily_bonus(payload: AuthInput):
    data = load_data()
    user = find_user(data, payload.username)
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Authentication failed")
    if not user["is_approved"]:
        raise HTTPException(status_code=403, detail="Account not approved")

    now = datetime.now()
    if user["last_bonus_time"]:
        last = datetime.fromisoformat(user["last_bonus_time"])
        if (now - last) < timedelta(hours=24):
            raise HTTPException(status_code=400, detail="Bonus already claimed")

    bonus = 0.1 * user["balance"]
    user["balance"] += bonus
    user["earnings"] += bonus
    user["last_bonus_time"] = now.isoformat()
    save_data(data)
    return {"message": f"Daily bonus of {bonus:.2f} credited", "bonus": bonus}

@app.post("/admin/approve_user")
def approve_user(payload: ApproveUserInput):
    data = load_data()
    admin = find_user(data, payload.admin_username)
    if not admin or not bcrypt.checkpw(payload.admin_password.encode(), admin["password"].encode()) or not admin.get("is_admin"):
        raise HTTPException(status_code=401, detail="Admin authentication failed")
    user = find_user(data, payload.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user["is_approved"]:
        raise HTTPException(status_code=400, detail="User already approved")
    user["is_approved"] = True
    save_data(data)
    return {"message": f"User {payload.username} approved"}

@app.post("/admin/reset_password")
def reset_password(payload: ResetPasswordInput):
    data = load_data()
    admin = find_user(data, payload.admin_username)
    if not admin or not bcrypt.checkpw(payload.admin_password.encode(), admin["password"].encode()) or not admin.get("is_admin"):
        raise HTTPException(status_code=401, detail="Admin authentication failed")
    user = find_user(data, payload.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["password"] = bcrypt.hashpw(payload.new_password.encode(), bcrypt.gensalt()).decode()
    save_data(data)
    return {"message": f"Password for {payload.username} has been reset"}

@app.post("/profile")
def profile(payload: AuthInput, request: Request):
    data = load_data()
    user = find_user(data, payload.username)
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Authentication failed")
    base_url = str(request.base_url).rstrip("/")
    return {
        "username": user["username"],
        "email": user["email"],
        "balance": user["balance"],
        "earnings": user["earnings"],
        "total_invested": user["total_invested"],
        "is_approved": user["is_approved"],
        "is_admin": user["is_admin"],
        "referral_link": f"{base_url}/register?ref={user['referral_code']}",
        "last_bonus_time": user["last_bonus_time"]
    }
