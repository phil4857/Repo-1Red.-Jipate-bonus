from fastapi import FastAPI, HTTPException
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
    allow_origins=["*"],  # Replace with ["https://your-vercel-app.vercel.app"] in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Password Hashing ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === Paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# === I/O Helpers ===
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

class ResetPasswordData(BaseModel):
    admin_username: str
    admin_password: str
    target_username: str
    new_password: str

# === Routes ===

@app.get("/")
def root():
    return {"message": "Jipate Bonus backend is running ✅"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/register")
def register(data: RegisterData):
    users = read_data(USERS_FILE)

    username = data.username.strip()
    number = data.number.strip()
    password = data.password
    confirm = data.confirm

    if not username or not number or not password or not confirm:
        raise HTTPException(status_code=400, detail="All fields are required")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if password != confirm:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if not number.isdigit() or len(number) != 10:
        raise HTTPException(status_code=400, detail="Phone number must be exactly 10 digits")
    for user in users.values():
        if user["number"] == number:
            raise HTTPException(status_code=400, detail="Phone number already registered")

    users[username] = {
        "username": username,
        "number": number,
        "password_hash": pwd_context.hash(password),
        "referral": data.referral,
        "referred_users": [],
        "approved": username == "admin",
        "is_admin": username == "admin",
        "balance": 0.0,
        "earnings": 0.0,
        "last_earning_time": time.time(),
        "registered_at": datetime.utcnow().isoformat()
    }

    if data.referral and data.referral in users:
        users[data.referral]["referred_users"].append(username)

    write_data(USERS_FILE, users)
    logger.info(f"✅ Registered: {username}")

    return {
        "message": "Registration successful",
        "username": username,
        "is_admin": username == "admin",
        "redirect": "admin.html" if username == "admin" else "dashboard.html"
    }

@app.post("/login")
def login(data: LoginData):
    users = read_data(USERS_FILE)
    username = data.username.strip()
    password = data.password

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    user = users.get(username)
    if not user or not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not yet approved by admin")

    logger.info(f"🔓 Login successful: {username}")

    return {
        "message": f"Welcome back {username}",
        "username": username,
        "is_admin": user.get("is_admin", False),
        "redirect": "admin.html" if user.get("is_admin") else "dashboard.html"
    }

@app.get("/users")
def get_users():
    users = read_data(USERS_FILE)
    return list(users.values())

@app.post("/admin/reset-password")
def reset_password(data: ResetPasswordData):
    users = read_data(USERS_FILE)

    admin = users.get(data.admin_username)
    if not admin or not admin.get("is_admin") or not pwd_context.verify(data.admin_password, admin["password_hash"]):
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid admin credentials")

    if data.target_username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    users[data.target_username]["password_hash"] = pwd_context.hash(data.new_password)
    write_data(USERS_FILE, users)
    logger.info(f"🔁 Password reset for {data.target_username} by {data.admin_username}")

    return {"message": f"Password for {data.target_username} has been reset successfully"}
