# main.py
from fastapi import FastAPI, Form, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any
import bcrypt, time, secrets, os

app = FastAPI()

# ------------------- CORS -------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- IN-MEMORY STORAGE -------------------
users: Dict[str, Dict[str, Any]] = {}
investments: Dict[str, Dict[str, Any]] = {}     # username -> investment dict (pending/approved)
withdrawals: Dict[str, Dict[str, Any]] = {}     # username -> withdrawal dict (pending/approved)

# ------------------- PLATFORM CONFIG -------------------
PLATFORM_NAME = "Mkoba Wallet"
PAYMENT_NUMBER = "0739075065"

# ------------------- ADMIN CONFIG -------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin4857")
ADMIN_TOKEN = "admin_static_token"  # legacy static token (kept for compatibility)
ADMIN_TOKENS: Dict[str, float] = {}  # dynamic token -> issued_time
ADMIN_TOKEN_TTL = 600  # seconds (10 minutes)

# ------------------- MODELS -------------------
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: Optional[str] = None
    referred_users: list[str] = Field(default_factory=list)
    balance: float = 0.0          # withdrawable funds (earnings/referral bonuses)
    earnings: float = 0.0         # cumulative earnings (for display)
    principal: float = 0.0        # invested principal (locked / not withdrawable)
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
    """Remove expired admin tokens."""
    now = time.time()
    expired = [t for t, ts in ADMIN_TOKENS.items() if now - ts > ADMIN_TOKEN_TTL]
    for t in expired:
        ADMIN_TOKENS.pop(t, None)

def admin_auth(authorization: str = Header(None)):
    """
    Dependency used for admin endpoints.
    Accepts static ADMIN_TOKEN (legacy) OR a dynamic token present in ADMIN_TOKENS (and not expired).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]

    # static token: still accepted (useful when testing with a known token)
    if token == ADMIN_TOKEN:
        return True

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
    """
    Register a user. Supports referral via form field or ?ref=username on the URL.
    """
    # if referral not given in form, try query param (for referral links)
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
    """
    Shared login endpoint for users and admin.
    Admin credentials return is_admin=True and a token (dynamic).
    """
    content_type = (request.headers.get("content-type") or "")
    if "application/json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing username or password")

    # Admin login path
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = secrets.token_hex(16)
        ADMIN_TOKENS[token] = time.time()
        return {
            "message": "Admin login successful",
            "is_admin": True,
            "token": token,
            "username": ADMIN_USERNAME
        }

    # Normal user login
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

# Also accept /admin/login (some frontends call this directly)
@app.post("/admin/login")
async def admin_login(request: Request):
    content_type = (request.headers.get("content-type") or "")
    if "application/json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

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
    # present withdrawable balance and locked principal separately
    return {
        "username": u["username"],
        "number": u["number"],
        "balance": u.get("balance", 0.0),
        "earnings": u.get("earnings", 0.0),
        "principal": u.get("principal", 0.0),
        "approved": u.get("approved", False),
        "referral": u.get("referral"),
        "referred_users": u.get("referred_users", []),
        "bonus_days_remaining": u.get("bonus_days_remaining", 0),
        "last_earning_time": u.get("last_earning_time", 0)
    }

@app.post("/invest")
async def invest(request: Request):
    """
    Create a pending investment. Admin must approve later.
    (Do NOT move principal here; do that on admin approval.)
    """
    content_type = (request.headers.get("content-type") or "")
    if "application/json" in content_type:
        body = await request.json()
        username = body.get("username")
        amount = body.get("amount")
        tx_ref = body.get("transaction_ref") or body.get("tx_ref") or ""
    else:
        form = await request.form()
        username = form.get("username")
        amount = form.get("amount")
        tx_ref = form.get("transaction_ref") or form.get("tx_ref") or ""

    if username is None or amount is None:
        raise HTTPException(status_code=400, detail="username and amount required")

    try:
        amount = float(amount)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid amount")

    if amount < 500:
        raise HTTPException(status_code=400, detail="Minimum investment is KES 500")

    u = users.get(username)
    if not u or not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not approved")

    # create or replace pending investment record
    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=tx_ref or f"tx-{int(time.time())}",
        timestamp=datetime.now()
    ).dict()

    return {
        "message": "Investment submitted. Pending approval.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER
    }

@app.post("/bonus/grab")
def grab_bonus(username: str = Form(...)):
    """
    User claims daily bonus. Requires an approved investment.
    Bonus = 10% of invested amount. Bonus goes to withdrawable balance and earnings.
    """
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
    u["balance"] = u.get("balance", 0.0) + bonus      # withdrawable
    u["earnings"] = u.get("earnings", 0.0) + bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] = u.get("bonus_days_remaining", 0) - 1

    return {
        "message": f"Bonus KES {bonus:.2f} credited",
        "bonus": bonus,
        "balance": u["balance"],
        "days_remaining": u["bonus_days_remaining"]
    }

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    """
    Create a pending withdrawal request. Withdrawn from withdrawable balance only on admin approval.
    User cannot withdraw principal.
    """
    u = users.get(username)
    inv = investments.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    # check allowed day if needed (original logic only allowed Mondays)
    if datetime.today().weekday() != 0:
        raise HTTPException(status_code=400, detail="Withdrawals only on Mondays")
    if not inv or not inv.get("approved", False):
        raise HTTPException(status_code=400, detail="No approved investment")

    try:
        amount = float(amount)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid amount")

    min_req = 0.3 * inv["amount"]
    if amount < min_req:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal is 30%: KES {min_req:.2f}")

    if u.get("balance", 0.0) < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # create pending withdrawal; DO NOT deduct balance here (deduct at admin approval)
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
def validate_admin(authorization: str = Header(None)):
    """
    Validate token for front-end. Accept static or dynamic token.
    Returns {"valid": True} on success so front-end can rely on it.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split()[1]
    prune_admin_tokens()
    if token == ADMIN_TOKEN or token in ADMIN_TOKENS:
        return {"valid": True}
    raise HTTPException(status_code=403, detail="Invalid or expired admin token")

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
    # static token: return ok but nothing to remove
    if token == ADMIN_TOKEN:
        return {"message": "Logged out (static token ignored server-side)"}
    raise HTTPException(status_code=403, detail="Invalid admin token")

@app.post("/admin/refresh")
def admin_refresh(authorization: str = Header(None)):
    """
    Refresh admin token: replace old dynamic token with a new one and extend TTL.
    Returns 'new_token' to the frontend.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    old_token = authorization.split()[1]
    prune_admin_tokens()
    if old_token in ADMIN_TOKENS:
        ADMIN_TOKENS.pop(old_token, None)
        new_token = secrets.token_hex(16)
        ADMIN_TOKENS[new_token] = time.time()
        return {"message": "Admin token refreshed", "new_token": new_token}
    if old_token == ADMIN_TOKEN:
        return {"message": "Static admin token does not require refresh"}
    raise HTTPException(status_code=403, detail="Invalid or expired admin token")

@app.get("/admin/users")
def get_all_users(_: bool = Depends(admin_auth)):
    """
    Return list of users with fields expected by frontend:
      username, number, approved, balance, earnings, referral, referred_users,
      total_invested, investment_approved, pending_withdrawal, principal
    """
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
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    amt = inv["amount"]
    u["principal"] = u.get("principal", 0.0) + amt
    u["bonus_days_remaining"] = 30 if amt < 1000 else 60 if amt < 3000 else 90

    # referral bonus (withdrawable)
    ref = u.get("referral")
    if ref and ref in users:
        ref_bonus = amt * 0.05
        users[ref]["balance"] = users[ref].get("balance", 0.0) + ref_bonus
        users[ref]["earnings"] = users[ref].get("earnings", 0.0) + ref_bonus

    return {"message": f"Investment for {username} approved"}

@app.post("/admin/approve_withdrawal")
def approve_withdrawal(username: str = Form(...), _: bool = Depends(admin_auth)):
    w = withdrawals.get(username)
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    if w.get("approved", False):
        return {"message": "Already approved"}

    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    amt = w["amount"]
    if u.get("balance", 0.0) < amt:
        raise HTTPException(status_code=400, detail="Insufficient balance to approve withdrawal")

    # Deduct balance and mark approved
    u["balance"] = u.get("balance", 0.0) - amt
    w["approved"] = True
    return {"message": f"Withdrawal of KES {amt:.2f} approved"}

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

    investments.pop(username, None)
    withdrawals.pop(username, None)
    for ref_u in users.values():
        if username in ref_u.get("referred_users", []):
            ref_u["referred_users"].remove(username)

    return {"message": f"User {username} terminated successfully"}
