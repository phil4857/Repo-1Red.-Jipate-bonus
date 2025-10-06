# main.py
from fastapi import FastAPI, Form, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
import bcrypt, time, secrets
from typing import Optional, Dict, Any

app = FastAPI()

# ------------------- CORS SETUP -------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ tighten this (or set to your frontend) in production
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

# ------------------- ADMIN AUTH -------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin4857"
ADMIN_TOKEN = "admin_static_token"  # legacy static token (still accepted)
ADMIN_TOKENS: Dict[str, float] = {}  # dynamic session tokens (token -> issued_time)
ADMIN_TOKEN_TTL_SECONDS = 600  # tokens expire after 10 minutes (adjustable)

# ------------------- MODELS -------------------
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: Optional[str] = None
    referred_users: list[str] = Field(default_factory=list)
    balance: float = 0.0            # withdrawable funds (earnings/referral bonuses)
    earnings: float = 0.0          # cumulative earnings (for display)
    principal: float = 0.0         # invested principal (NOT withdrawable)
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

def check_pwd(pw: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), h.encode())
    except Exception:
        return False

def prune_admin_tokens():
    """Remove expired admin tokens."""
    now = time.time()
    expired = [t for t, ts in ADMIN_TOKENS.items() if now - ts > ADMIN_TOKEN_TTL_SECONDS]
    for t in expired:
        ADMIN_TOKENS.pop(t, None)

def admin_auth(authorization: str = Header(None)):
    """
    Accept either the static ADMIN_TOKEN or any token present in ADMIN_TOKENS (and not expired).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]

    # static token allowed (legacy)
    if token == ADMIN_TOKEN:
        return True

    # prune expired tokens first
    prune_admin_tokens()

    if token in ADMIN_TOKENS:
        return True

    raise HTTPException(status_code=403, detail="Invalid admin token")

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
    """
    Register new user.
    Referral may be provided as a form field `referral` or via the query param `?ref=`.
    """
    if not referral:
        referral = request.query_params.get("ref")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    pw_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=pw_hash,
        referral=referral
    ).dict()

    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    return {
        "message": f"User {username} registered. Awaiting approval.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/login")
async def login(request: Request):
    data = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing username or password")

    # Admin login -> issue dynamic token
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        # generate single-use short-lived token
        token = secrets.token_hex(16)
        ADMIN_TOKENS[token] = time.time()
        return {
            "message": "Admin login successful",
            "is_admin": True,
            "is_approved": True,
            "token": token,
            "username": ADMIN_USERNAME
        }

    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not yet approved")

    return {
        "message": f"Welcome {username}",
        "is_admin": False,
        "is_approved": True,
        "username": username
    }

@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": u["username"],
        "number": u["number"],
        "balance": u.get("balance", 0.0),        # withdrawable (earnings)
        "earnings": u.get("earnings", 0.0),
        "principal": u.get("principal", 0.0),    # invested principal (unwithdrawable)
        "approved": u.get("approved", False),
        "referral": u.get("referral"),
        "referred_users": u.get("referred_users", []),
        "bonus_days_remaining": u.get("bonus_days_remaining", 0),
        "last_earning_time": u.get("last_earning_time", 0)
    }

@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    bonus_available = False
    bonus_message = "No approved investment"
    if inv and inv.get("approved", False):
        now = time.time()
        if u["bonus_days_remaining"] > 0 and now - u["last_earning_time"] >= 86400:
            bonus_available = True
            bonus_message = "Bonus available"
        else:
            bonus_message = "Already claimed or period ended"

    return {
        "username": u["username"],
        "balance": u["balance"],
        "earnings": u["earnings"],
        "principal": u.get("principal", 0.0),
        "approved": u["approved"],
        "referral": u["referral"],
        "referred_users": u["referred_users"],
        "investment_amount": inv["amount"] if inv else 0,
        "bonus_available": bonus_available,
        "bonus_message": bonus_message,
        "bonus_days_remaining": u["bonus_days_remaining"],
        "last_bonus_time": datetime.fromtimestamp(u["last_earning_time"]).isoformat() if u["last_earning_time"] else None,
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/invest")
async def invest(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        username = body.get("username")
        amount = body.get("amount")
        transaction_ref = body.get("transaction_ref") or body.get("tx_ref") or ""
    else:
        form = await request.form()
        username = form.get("username")
        amount = form.get("amount")
        transaction_ref = form.get("transaction_ref") or form.get("tx_ref") or ""

    if username is None or amount is None:
        raise HTTPException(status_code=400, detail="username and amount required")

    try:
        amount = float(amount)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid amount")

    u = users.get(username)
    if not u or not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not approved")
    if amount < 500:
        raise HTTPException(status_code=400, detail="Minimum investment is KES 500")

    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=transaction_ref or f"tx-{int(time.time())}",
        timestamp=datetime.now()
    ).dict()
    return {
        "message": "Investment submitted. Pending approval.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv or not inv.get("approved", False):
        raise HTTPException(status_code=400, detail="No approved investment")
    if u["bonus_days_remaining"] <= 0:
        raise HTTPException(status_code=400, detail="No bonus period left")
    now = time.time()
    if now - u["last_earning_time"] < 86400:
        raise HTTPException(status_code=400, detail="Bonus already claimed today")

    bonus = inv["amount"] * 0.10
    # bonus is earnings: goes to both balance (withdrawable) and earnings (for display)
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] -= 1

    return {
        "message": f"Bonus KES {bonus:.2f} credited",
        "bonus": bonus,
        "balance": u["balance"],
        "days_remaining": u["bonus_days_remaining"]
    }

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    # withdrawals only allowed on Mondays (as before)
    if datetime.today().weekday() != 0:
        raise HTTPException(status_code=400, detail="Withdrawals only on Mondays")
    if not inv or not inv.get("approved", False):
        raise HTTPException(status_code=400, detail="No approved investment")

    min_req = 0.3 * inv["amount"]
    if amount < min_req:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal is 30%: KES {min_req:.2f}")

    # Withdraw only from user's withdrawable balance (earnings/referral bonuses).
    if u["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    withdrawals[username] = WithdrawalRequest(
        username=username,
        amount=amount,
        timestamp=datetime.now()
    ).dict()
    return {"message": f"Withdrawal KES {amount:.2f} requested. Pending approval."}

@app.get("/referrals/{username}")
def referrals(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u.get("referred_users", [])

# ------------------- ADMIN ROUTES -------------------
@app.get("/admin/validate")
def validate_admin(_: bool = Depends(admin_auth)):
    """Simple admin token validator for frontends."""
    return {"valid": True}

@app.post("/admin/logout")
def admin_logout(authorization: str = Header(None)):
    """Invalidate the provided admin token (if dynamic)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]
    # Remove dynamic token if present
    if token in ADMIN_TOKENS:
        ADMIN_TOKENS.pop(token, None)
        return {"message": "Logged out"}
    # allow static token logout response for completeness
    if token == ADMIN_TOKEN:
        return {"message": "Logged out (static token ignored server-side)"}
    raise HTTPException(status_code=403, detail="Invalid admin token")

@app.get("/admin/users")
def get_all_users(_: bool = Depends(admin_auth)):
    out = []
    for uname, u in users.items():
        inv = investments.get(uname)
        w = withdrawals.get(uname)
        out.append({
            "username": u["username"],
            "number": u["number"],
            "approved": u.get("approved", False),
            "balance": u.get("balance", 0.0),
            "earnings": u.get("earnings", 0.0),
            "principal": u.get("principal", 0.0),
            "referral": u.get("referral"),
            "referred_users": u.get("referred_users", []),
            "total_invested": inv["amount"] if inv else 0,
            "investment_approved": inv.get("approved", False) if inv else False,
            "pending_withdrawal": w["amount"] if w and not w.get("approved", False) else 0
        })
    return out

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
    if inv.get("approved", False):
        return {"message": "Already approved"}

    inv["approved"] = True
    u = users[username]
    amt = inv["amount"]

    # **Important change**: keep invested principal separate and unwithdrawable.
    u["principal"] = u.get("principal", 0.0) + amt

    # Set bonus period
    u["bonus_days_remaining"] = 30 if amt < 1000 else 60 if amt < 3000 else 90

    # Referral bonus (still goes to referral's balance and earnings - withdrawable)
    ref = u.get("referral")
    if ref in users:
        users[ref]["balance"] += amt * 0.05
        users[ref]["earnings"] += amt * 0.05

    return {"message": f"Investment for {username} approved"}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    if w.get("approved", False):
        return {"message": "Already approved"}

    u = users[username]
    if u["balance"] < w["amount"]:
        raise HTTPException(status_code=400, detail="Insufficient balance to approve withdrawal")

    u["balance"] -= w["amount"]
    w["approved"] = True
    return {"message": f"Withdrawal of KES {w['amount']:.2f} approved"}

@app.post("/admin/reset-password")
def reset_password(target_username: str = Form(...), new_password: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.get(target_username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"Password for {target_username} reset successfully"}

@app.post("/admin/terminate_user")
def terminate_user(username: str = Form(...), _: bool = Depends(admin_auth)):
    u = users.pop(username, None)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    # Clean up related records
    investments.pop(username, None)
    withdrawals.pop(username, None)
    for ref_u in users.values():
        if username in ref_u.get("referred_users", []):
            ref_u["referred_users"].remove(username)

    return {"message": f"User {username} terminated successfully"}
