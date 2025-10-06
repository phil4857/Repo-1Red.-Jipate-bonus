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
    allow_origins=["*"],  # TODO: Restrict to frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- STORAGE -------------------
users: Dict[str, Dict[str, Any]] = {}
investments: Dict[str, Dict[str, Any]] = {}
withdrawals: Dict[str, Dict[str, Any]] = {}

# ------------------- CONFIG -------------------
PLATFORM_NAME = "Mkoba Wallet"
PAYMENT_NUMBER = "0739075065"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"
ADMIN_TOKENS: Dict[str, float] = {}
ADMIN_TOKEN_TTL = 600  # 10 minutes

# ------------------- MODELS -------------------
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: Optional[str] = None
    referred_users: list[str] = Field(default_factory=list)
    balance: float = 0.0        # withdrawable
    earnings: float = 0.0       # total earnings
    principal: float = 0.0      # locked investment
    last_earning_time: float = 0.0
    bonus_days_remaining: int = 0


class Investment(BaseModel):
    username: str
    amount: float
    transaction_ref: str
    approved: bool = False
    timestamp: datetime


class Withdrawal(BaseModel):
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
    if token in ADMIN_TOKENS:
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
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    users[username] = User(
        username=username,
        number=number,
        password_hash=hash_pwd(password),
        referral=referral
    ).dict()

    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    return {"message": f"User {username} registered successfully. Awaiting admin approval."}


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

    # --- Admin login ---
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = secrets.token_hex(16)
        ADMIN_TOKENS[token] = time.time()
        return {"message": "Admin login successful", "is_admin": True, "token": token, "username": ADMIN_USERNAME}

    # --- Normal user login ---
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not u.get("approved"):
        raise HTTPException(status_code=403, detail="Account not yet approved")

    return {"message": f"Welcome {username}", "is_admin": False, "username": username}


@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": u["username"],
        "number": u["number"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "principal": u["principal"],
        "approved": u["approved"],
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "bonus_days_remaining": u["bonus_days_remaining"]
    }


@app.post("/invest")
async def invest(request: Request):
    data = await request.form()
    username = data.get("username")
    amount = float(data.get("amount", 0))
    tx_ref = data.get("transaction_ref") or f"tx-{int(time.time())}"

    if amount < 500:
        raise HTTPException(status_code=400, detail="Minimum investment is 500")

    u = users.get(username)
    if not u or not u["approved"]:
        raise HTTPException(status_code=403, detail="User not approved")

    investments[username] = Investment(
        username=username, amount=amount, transaction_ref=tx_ref, timestamp=datetime.now()
    ).dict()

    u["principal"] += amount  # lock it (not withdrawable yet)

    return {"message": f"Investment of {amount} received, awaiting admin approval."}


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
    u["balance"] += bonus  # withdrawable
    u["earnings"] += bonus
    u["bonus_days_remaining"] -= 1
    u["last_earning_time"] = now

    return {"message": f"Bonus {bonus:.2f} credited", "balance": u["balance"]}


@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if datetime.today().weekday() != 0:
        raise HTTPException(status_code=400, detail="Withdrawals only allowed on Mondays")

    if u["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    withdrawals[username] = Withdrawal(
        username=username, amount=amount, timestamp=datetime.now()
    ).dict()

    u["balance"] -= amount
    return {"message": f"Withdrawal of {amount:.2f} submitted for admin approval."}


# ------------------- ADMIN ROUTES -------------------
@app.get("/admin/validate")
def validate_admin(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]
    prune_admin_tokens()
    if token in ADMIN_TOKENS:
        return {"valid": True}
    raise HTTPException(status_code=403, detail="Invalid or expired token")


@app.get("/admin/refresh")
def refresh_admin_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]
    prune_admin_tokens()
    if token not in ADMIN_TOKENS:
        raise HTTPException(status_code=403, detail="Expired token")

    new_token = secrets.token_hex(16)
    ADMIN_TOKENS[new_token] = time.time()
    del ADMIN_TOKENS[token]
    return {"new_token": new_token}


@app.get("/admin/users")
def list_users(_: bool = Depends(admin_auth)):
    return list(users.values())


@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["approved"] = True
    return {"message": f"✅ User {username} approved."}


@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...), _: bool = Depends(admin_auth)):
    inv = investments.get(username)
    u = users.get(username)
    if not u or not inv:
        raise HTTPException(status_code=404, detail="No investment found")
    inv["approved"] = True
    u["bonus_days_remaining"] = 7
    return {"message": f"💰 Investment for {username} approved. Bonus active for 7 days."}


@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(status_code=404, detail="No withdrawal found")
    w["approved"] = True
    return {"message": f"📤 Withdrawal for {username} approved."}


@app.post("/admin/reset-password")
def reset_password(target_username: str = Form(...), new_password: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(target_username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"🔑 Password for {target_username} reset."}


@app.post("/admin/terminate_user")
def terminate_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    if username in users:
        users.pop(username)
        investments.pop(username, None)
        withdrawals.pop(username, None)
        return {"message": f"❌ User {username} terminated."}
    raise HTTPException(status_code=404, detail="User not found")
