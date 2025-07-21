from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime
import os, json, time, logging

# === Logging ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === App ===
app = FastAPI()

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://your-vercel-app.vercel.app",  # Replace with actual deployed frontend
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === Data Paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
INVESTMENTS_FILE = os.path.join(DATA_DIR, "investments.json")

def read_data(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def write_data(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

# === Models ===
class RegisterData(BaseModel):
    username: str
    number: str
    password: str
    confirm: str
    referral: str | None = None

class LoginData(BaseModel):
    username: str
    password: str

# === Register Route ===
@app.post("/register")
def register(data: RegisterData):
    users = read_data(USERS_FILE)

    if data.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if data.password != data.confirm:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if not data.number.isdigit() or len(data.number) < 10:
        raise HTTPException(status_code=400, detail="Invalid phone number")
    for user in users.values():
        if user["number"] == data.number:
            raise HTTPException(status_code=400, detail="Phone number already registered")

    users[data.username] = {
        "username": data.username,
        "number": data.number,
        "password_hash": pwd_context.hash(data.password),
        "referral": data.referral,
        "referred_users": [],
        "approved": data.username == "admin",
        "is_admin": data.username == "admin",
        "balance": 0.0,
        "earnings": 0.0,
        "last_earning_time": time.time(),
        "registered_at": datetime.utcnow().isoformat()
    }

    if data.referral and data.referral in users:
        users[data.referral]["referred_users"].append(data.username)

    write_data(USERS_FILE, users)
    logger.info(f"✅ Registered: {data.username}")

    return {
        "message": "Registration successful",
        "username": data.username,
        "is_admin": data.username == "admin",
        "redirect": "admin.html" if data.username == "admin" else "dashboard.html"
    }

# === Login Route ===
@app.post("/login")
def login(data: LoginData):
    users = read_data(USERS_FILE)
    user = users.get(data.username)

    if not user or not pwd_context.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not yet approved by admin")

    logger.info(f"🔓 Login: {data.username}")

    return {
        "message": f"Welcome back {data.username}",
        "username": data.username,
        "is_admin": user.get("is_admin", False),
        "redirect": "admin.html" if user.get("is_admin") else "dashboard.html"
    }
