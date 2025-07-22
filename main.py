from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime
import os, json, time, logging

=== Logging Setup ===

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(name)

=== FastAPI App Setup ===

app = FastAPI()

=== CORS Setup ===

app.add_middleware(
CORSMiddleware,
allow_origins=[""],  # 🔐 In production, use specific origins
allow_credentials=True,
allow_methods=[""],
allow_headers=["*"],
)

=== Password Hashing ===

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

=== File Paths ===

BASE_DIR = os.path.dirname(os.path.abspath(file))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

=== I/O Utilities ===

def read_data(filepath):
if os.path.exists(filepath):
with open(filepath, "r") as f:
return json.load(f)
return {}

def write_data(filepath, data):
os.makedirs(os.path.dirname(filepath), exist_ok=True)
with open(filepath, "w") as f:
json.dump(data, f, indent=4)

=== Ensure users.json Exists with Admin Account ===

if not os.path.exists(USERS_FILE):
os.makedirs(DATA_DIR, exist_ok=True)
default_admin = {
"admin": {
"username": "admin",
"number": "0700000000",
"password_hash": pwd_context.hash("adminmutegi4857"),
"referral": None,
"referred_users": [],
"approved": True,
"is_admin": True,
"balance": 0.0,
"earnings": 0.0,
"last_earning_time": time.time(),
"registered_at": datetime.utcnow().isoformat()
}
}
write_data(USERS_FILE, default_admin)
logger.info("✅ Default admin account created")

=== Models ===

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

class ApproveUserData(BaseModel):
admin_username: str
admin_password: str
target_username: str

=== Routes ===

@app.get("/")
def root():
return {"message": "Jipate Bonus backend is running ✅"}

@app.get("/health")
def health():
return {"status": "ok"}

@app.post("/register")
def register(data: RegisterData):
users = read_data(USERS_FILE)
username = data.username.strip().lower()
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
logger.info(f"✅ Registered user: {username}")  

return {  
    "message": "Registration successful",  
    "username": username,  
    "is_admin": username == "admin",  
    "redirect": "admin.html" if username == "admin" else "dashboard.html"  
}

@app.post("/login")
def login(data: LoginData):
users = read_data(USERS_FILE)
username = data.username.strip().lower()
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

@app.get("/user/{username}")
def get_user(username: str):
users = read_data(USERS_FILE)
user = users.get(username)
if not user:
raise HTTPException(status_code=404, detail="User not found")

return {  
    "username": user["username"],  
    "number": user["number"],  
    "referral": user.get("referral"),  
    "approved": user.get("approved", False),  
    "balance": user.get("balance", 0.0),  
    "earnings": user.get("earnings", 0.0),  
    "registered_at": user.get("registered_at")  
}

@app.get("/referrals/{username}")
def get_referrals(username: str):
users = read_data(USERS_FILE)
user = users.get(username)
if not user:
raise HTTPException(status_code=404, detail="User not found")

return user.get("referred_users", [])

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
users = read_data(USERS_FILE)
user = users.get(username)

if not user:  
    raise HTTPException(status_code=404, detail="User not found")  
if amount <= 0:  
    raise HTTPException(status_code=400, detail="Invalid investment amount")  

user["balance"] += amount  
users[username] = user  
write_data(USERS_FILE, users)  

logger.info(f"💰 {username} invested KES {amount} via {transaction_ref}")  
return {"message": f"Investment of KES {amount} recorded successfully."}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
users = read_data(USERS_FILE)
user = users.get(username)

if not user:  
    raise HTTPException(status_code=404, detail="User not found")  
if amount <= 0 or amount > user["balance"]:  
    raise HTTPException(status_code=400, detail="Invalid withdrawal amount")  

user["balance"] -= amount  
users[username] = user  
write_data(USERS_FILE, users)  

logger.info(f"🏧 {username} withdrew KES {amount}")  
return {"message": f"Withdrawal of KES {amount} submitted for processing."}

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

@app.post("/admin/approve-user")
def approve_user(data: ApproveUserData):
users = read_data(USERS_FILE)

admin = users.get(data.admin_username)  
if not admin or not admin.get("is_admin") or not pwd_context.verify(data.admin_password, admin["password_hash"]):  
    raise HTTPException(status_code=403, detail="Unauthorized: Invalid admin credentials")  

if data.target_username not in users:  
    raise HTTPException(status_code=404, detail="User not found")  

users[data.target_username]["approved"] = True  
write_data(USERS_FILE, users)  
logger.info(f"✅ User {data.target_username} approved by admin {data.admin_username}")  

return {"message": f"User {data.target_username} has been approved successfully"}

