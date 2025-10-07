# main.py
from fastapi import FastAPI, Form, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any
import bcrypt, time, secrets

app = FastAPI()

# ------------------- CORS -------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- IN-MEMORY STORAGE -------------------
users: Dict[str, Dict[str, Any]] = {}
investments: Dict[str, Dict[str, Any]] = {}
withdrawals: Dict[str, Dict[str, Any]] = {}

# ------------------- PLATFORM CONFIG -------------------
PLATFORM_NAME = "Mkoba Wallet"
PAYMENT_NUMBER = "0739075065"

# ------------------- ADMIN CONFIG -------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"
ADMIN_TOKEN = "admin_static_token"
ADMIN_TOKENS: Dict[str, float] = {}
ADMIN_TOKEN_TTL = 600  # seconds (10 min)

# ------------------- MODELS -------------------
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: Optional[str] = None
    referred_users: list[str] = Field(default_factory=list)
    balance: float = 0.0
    earnings: float = 0.0
    principal: float = 0.0
    last_earning_time: float = 0.0
    bonus_days_remaining: int = 0

class Investment(BaseModel):
    username: str
    amount: float
    transaction_ref: str
    approved: bool = False
    timestamp: datetime

class WithdrawalRequest(BaseModel):
    username: str
    amount: float
    approved: bool = False
    timestamp: datetime

# ------------------- UTILITIES -------------------
def hash_pwd(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pwd(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def prune_admin_tokens():
    now = time.time()
    expired = [t for t, ts in ADMIN_TOKENS.items() if now - ts > ADMIN_TOKEN_TTL]
    for t in expired:
        ADMIN_TOKENS.pop(t, None)

def admin_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]
    prune_admin_tokens()
    if token == ADMIN_TOKEN or token in ADMIN_TOKENS:
        return True
    raise HTTPException(status_code=403, detail="Invalid or expired admin token")

# ------------------- BASIC ROUTES -------------------
@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time()}

@app.get("/platform/info")
def platform_info():
    return {"platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}

# ------------------- USER ROUTES -------------------
@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    referral: Optional[str] = Form(None),
):
    if not referral:
        referral = request.query_params.get("ref")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    users[username] = User(
        username=username,
        number=number,
        password_hash=hash_pwd(password),
        referral=referral,
    ).dict()

    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    return {
        "message": f"User {username} registered successfully. Awaiting approval.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER,
    }

@app.post("/login")
async def login(request: Request):
    if "application/json" in (request.headers.get("content-type") or ""):
        data = await request.json()
    else:
        data = dict(await request.form())

    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing credentials")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = secrets.token_hex(16)
        ADMIN_TOKENS[token] = time.time()
        return {
            "message": "Admin login successful",
            "is_admin": True,
            "token": token,
            "username": ADMIN_USERNAME,
        }

    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not u.get("approved"):
        raise HTTPException(status_code=403, detail="Account not approved")

    return {"message": f"Welcome {username}", "is_admin": False, "username": username}

@app.post("/admin/login")
async def admin_login(request: Request):
    if "application/json" in (request.headers.get("content-type") or ""):
        data = await request.json()
    else:
        data = dict(await request.form())

    username = data.get("username")
    password = data.get("password")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = secrets.token_hex(16)
        ADMIN_TOKENS[token] = time.time()
        return {"message": "Admin login successful", "token": token}
    raise HTTPException(status_code=403, detail="Invalid admin credentials")

@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u

@app.post("/invest")
async def invest(request: Request):
    if "application/json" in (request.headers.get("content-type") or ""):
        data = await request.json()
    else:
        data = dict(await request.form())

    username = data.get("username")
    amount = data.get("amount")
    tx_ref = data.get("transaction_ref") or f"tx-{int(time.time())}"

    if not username or not amount:
        raise HTTPException(status_code=400, detail="Missing fields")

    amount = float(amount)
    if amount < 500:
        raise HTTPException(status_code=400, detail="Minimum investment is 500")

    u = users.get(username)
    if not u or not u.get("approved"):
        raise HTTPException(status_code=403, detail="User not approved")

    investments[username] = Investment(
        username=username, amount=amount, transaction_ref=tx_ref, timestamp=datetime.now()
    ).dict()

    return {"message": "Investment submitted, awaiting approval"}

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv or not inv["approved"]:
        raise HTTPException(status_code=400, detail="No approved investment")
    if u["bonus_days_remaining"] <= 0:
        raise HTTPException(status_code=400, detail="No bonus days remaining")

    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(status_code=400, detail="Already claimed today")

    bonus = inv["amount"] * 0.10
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] -= 1

    return {"message": f"Bonus {bonus:.2f} credited", "balance": u["balance"]}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if datetime.today().weekday() != 0:
        raise HTTPException(status_code=400, detail="Withdrawals only on Monday")
    if not inv or not inv.get("approved"):
        raise HTTPException(status_code=400, detail="No approved investment")

    min_req = inv["amount"] * 0.3
    if amount < min_req:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal {min_req}")
    if u["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    withdrawals[username] = WithdrawalRequest(
        username=username, amount=amount, timestamp=datetime.now()
    ).dict()
    return {"message": f"Withdrawal {amount} requested"}

@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u.get("referred_users", [])

# ------------------- ADMIN ROUTES -------------------
@app.get("/admin/validate")
def validate_admin(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]
    prune_admin_tokens()
    if token == ADMIN_TOKEN or token in ADMIN_TOKENS:
        return {"valid": True}
    raise HTTPException(status_code=403, detail="Invalid or expired admin token")

@app.post("/admin/refresh")
def admin_refresh(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    old_token = authorization.split()[1]
    prune_admin_tokens()
    if old_token in ADMIN_TOKENS:
        ADMIN_TOKENS.pop(old_token, None)
        new_token = secrets.token_hex(16)
        ADMIN_TOKENS[new_token] = time.time()
        return {"message": "Token refreshed", "token": new_token}
    if old_token == ADMIN_TOKEN:
        return {"message": "Static admin token does not expire"}
    raise HTTPException(status_code=403, detail="Invalid or expired admin token")

@app.get("/admin/users")
def get_all_users(_: bool = Depends(admin_auth)):
    result = []
    for uname, u in users.items():
        inv = investments.get(uname)
        w = withdrawals.get(uname)
        result.append({
            "username": u["username"],
            "number": u["number"],
            "approved": u["approved"],
            "balance": u["balance"],
            "earnings": u["earnings"],
            "principal": u["principal"],
            "referral": u["referral"],
            "referred_users": u["referred_users"],
            "investment_approved": inv["approved"] if inv else False,
            "pending_withdrawal": w["amount"] if w and not w["approved"] else 0,
        })
    return result

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["approved"] = True
    return {"message": f"User {username} approved"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...), _: bool = Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(status_code=404, detail="Investment not found")
    if inv.get("approved"):
        return {"message": "Already approved"}

    inv["approved"] = True
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    amt = inv["amount"]
    u["principal"] += amt
    u["bonus_days_remaining"] = 30 if amt < 1000 else 60 if amt < 3000 else 90

    ref = u.get("referral")
    if ref and ref in users:
        ref_bonus = amt * 0.05
        users[ref]["balance"] += ref_bonus
        users[ref]["earnings"] += ref_bonus

    return {"message": f"Investment {amt} for {username} approved"}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    if w["approved"]:
        return {"message": "Already approved"}

    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    amt = w["amount"]
    if u["balance"] < amt:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    u["balance"] -= amt
    w["approved"] = True
    return {"message": f"Withdrawal {amt} approved"}

@app.post("/admin/reset-password")
def reset_password(username: str = Form(...), new_password: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"Password for {username} reset"}

@app.post("/admin/terminate_user")
def terminate_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    users.pop(username, None)
    investments.pop(username, None)
    withdrawals.pop(username, None)
    for ref_u in users.values():
        if username in ref_u.get("referred_users", []):
            ref_u["referred_users"].remove(username)
    return {"message": f"User {username} terminated"}
