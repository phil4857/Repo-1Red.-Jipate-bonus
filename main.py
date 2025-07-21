from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import datetime
import os, json, time, logging

# ===== LOGGING SETUP =====
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== APP INIT & CORS CONFIG =====
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://jipate-bonus-v1-fo81-32ecwht8n-phil4857s-projects.vercel.app",  # Frontend
        "https://jipate-bonus-v1-fo81-git-main-phil4857s-projects.vercel.app",   # Frontend (Git branch)
        "https://repo-1red-jipate-bonus-1.onrender.com",                         # Backend
        "http://localhost:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== INCLUDE ADMIN ROUTES =====
from admin import router as admin_router
app.include_router(admin_router)

# ===== PASSWORD HASHING =====
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ===== FILE PATHS =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
INVESTMENTS_FILE = os.path.join(DATA_DIR, "investments.json")

# ===== UTILITIES =====
def read_data(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def write_data(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

# ===== STARTUP LOG =====
@app.on_event("startup")
def startup_event():
    logger.info("🚀 Jipate Bonus Backend started successfully")

# ===== ROUTES =====

@app.get("/")
def root():
    return {"message": "Welcome to Jipate Bonus Investment Platform 🎉"}

@app.post("/register")
def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    referral: str = Form(None)
):
    users = read_data(USERS_FILE)

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if password != confirm:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if not number.isdigit() or len(number) < 10:
        raise HTTPException(status_code=400, detail="Invalid phone number")
    for user in users.values():
        if user["number"] == number:
            raise HTTPException(status_code=400, detail="Phone number already registered")

    users[username] = {
        "username": username,
        "number": number,
        "password_hash": pwd_context.hash(password),
        "referral": referral,
        "referred_users": [],
        "approved": False,
        "balance": 0.0,
        "earnings": 0.0,
        "last_earning_time": time.time(),
        "registered_at": datetime.utcnow().isoformat()
    }

    if referral in users:
        users[referral]["referred_users"].append(username)

    write_data(USERS_FILE, users)
    logger.info(f"✅ New registration: {username}")
    return {"message": "User registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    users = read_data(USERS_FILE)
    user = users.get(username)

    if not user or not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not yet approved by admin")

    logger.info(f"🔐 Login: {username}")
    return {"message": f"Welcome {username}"}

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    users = read_data(USERS_FILE)
    investments = read_data(INVESTMENTS_FILE)

    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if not users[username]["approved"]:
        raise HTTPException(status_code=403, detail="User is not approved")
    if username in investments:
        raise HTTPException(status_code=400, detail="User has already invested")
    if not transaction_ref.strip():
        raise HTTPException(status_code=400, detail="Transaction reference required")

    # 5% Sunday discount
    adjusted_amount = amount * (0.95 if datetime.utcnow().strftime("%A") == "Sunday" else 1.0)

    investments[username] = {
        "username": username,
        "amount": adjusted_amount,
        "transaction_ref": transaction_ref,
        "approved": False,
        "timestamp": datetime.utcnow().isoformat()
    }

    write_data(INVESTMENTS_FILE, investments)
    logger.info(f"💰 Investment submitted by {username}: KES {adjusted_amount:.2f}")
    return {"message": f"Investment of KES {adjusted_amount:.2f} submitted successfully"}

@app.post("/earnings/daily")
def credit_daily_earnings():
    users = read_data(USERS_FILE)
    investments = read_data(INVESTMENTS_FILE)
    now = time.time()
    count = 0

    for username, inv in investments.items():
        if not inv.get("approved"):
            continue
        user = users.get(username)
        if not user:
            continue
        if now - user.get("last_earning_time", 0) >= 86400:
            earning = inv["amount"] * 0.10
            user["balance"] += earning
            user["earnings"] += earning
            user["last_earning_time"] = now
            count += 1

    write_data(USERS_FILE, users)
    logger.info(f"✅ Credited daily earnings to {count} user(s)")
    return {"message": f"Earnings credited for {count} user(s)"}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    users = read_data(USERS_FILE)
    investments = read_data(INVESTMENTS_FILE)
    user = users.get(username)
    inv = investments.get(username)

    if not user or not inv:
        raise HTTPException(status_code=404, detail="User or investment not found")

    invested = inv["amount"]
    balance = user["balance"]

    if invested < 1000:
        limit = 150
    elif invested < 1500:
        limit = 300
    else:
        limit = invested * 0.3

    if amount > limit:
        raise HTTPException(status_code=400, detail=f"Withdrawal limit is {limit}")
    if amount > balance:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    user["balance"] -= amount
    write_data(USERS_FILE, users)
    logger.info(f"💸 Withdrawal by {username}: KES {amount:.2f}")
    return {"message": f"Withdrawal request of KES {amount:.2f} submitted"}
