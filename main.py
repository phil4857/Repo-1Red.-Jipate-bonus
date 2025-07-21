from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import datetime
import os, json, time, logging

# ===== Logging Setup =====
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== App Initialization =====
app = FastAPI()

# ===== CORS Configuration =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # local frontend
        "https://your-vercel-app.vercel.app",  # your production frontend (replace with actual)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Password Hashing =====
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ===== File Paths =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
INVESTMENTS_FILE = os.path.join(DATA_DIR, "investments.json")

# ===== Utility Functions =====
def read_data(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def write_data(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

@app.on_event("startup")
def startup_event():
    logger.info("🚀 Backend started")

@app.get("/")
def root():
    return {"message": "Jipate Bonus API is live ✅"}

# ===== Register Route =====
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
        "approved": username == "admin",  # auto approve admin
        "is_admin": username == "admin",
        "balance": 0.0,
        "earnings": 0.0,
        "last_earning_time": time.time(),
        "registered_at": datetime.utcnow().isoformat()
    }

    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    write_data(USERS_FILE, users)
    logger.info(f"✅ Registered: {username}")

    return {
        "message": "Registration successful",
        "username": username,
        "is_admin": username == "admin",
        "redirect": "admin.html" if username == "admin" else "dashboard.html"
    }

# ===== Login Route =====
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    users = read_data(USERS_FILE)
    user = users.get(username)

    if not user or not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not yet approved by admin")

    logger.info(f"🔓 Login: {username}")

    return {
        "message": f"Welcome back {username}",
        "username": username,
        "is_admin": user.get("is_admin", False),
        "redirect": "admin.html" if user.get("is_admin") else "dashboard.html"
    }

# ===== Investment Route =====
@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    users = read_data(USERS_FILE)
    investments = read_data(INVESTMENTS_FILE)

    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if not users[username]["approved"]:
        raise HTTPException(status_code=403, detail="Not approved")
    if username in investments:
        raise HTTPException(status_code=400, detail="Already invested")
    if not transaction_ref.strip():
        raise HTTPException(status_code=400, detail="Missing transaction reference")

    # Apply Sunday 5% discount
    today = datetime.utcnow().strftime("%A")
    adjusted_amount = amount * 0.95 if today == "Sunday" else amount

    investments[username] = {
        "username": username,
        "amount": adjusted_amount,
        "transaction_ref": transaction_ref,
        "approved": False,
        "timestamp": datetime.utcnow().isoformat()
    }

    write_data(INVESTMENTS_FILE, investments)
    logger.info(f"💰 Investment from {username}: {adjusted_amount}")

    return {"message": "Investment submitted", "amount": adjusted_amount}

# ===== Daily Earnings Route =====
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
        last_time = user.get("last_earning_time", 0)
        if now - last_time >= 86400:
            earning = inv["amount"] * 0.1
            user["balance"] += earning
            user["earnings"] += earning
            user["last_earning_time"] = now
            count += 1

    write_data(USERS_FILE, users)
    logger.info(f"✅ {count} users credited")

    return {"message": f"Credited daily earnings for {count} users"}

# ===== Withdrawal Route =====
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

    # Calculate limit
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
    logger.info(f"💸 {username} withdrew {amount}")

    return {"message": f"Withdrawal of KES {amount} successful"}
