# main.py
"""
FastAPI backend for Mkoba Wallet (user + hidden admin).

Features:
- User registration with Twilio OTP (server-side admin alert on registration).
- No STK/payment integration (removed).
- Admin endpoints secured: require admin token or X-ADMIN-SECRET header.
  Unauthorized requests return 404 to hide admin endpoints.
- Admin token issuance and refresh (simple in-memory token store).
- Endpoints aligned to the frontend you've provided:
  - Public user endpoints: /register, /verify-otp, /login, /dashboard, /invest, /bonus/grab, /platform/info
  - Admin endpoints: /admin/* (and mirrored under /dev-<ADMIN_PATH_TOKEN>-panel/*)
Environment variables (recommended in .env):
- TWILIO_SID
- TWILIO_AUTH_TOKEN
- TWILIO_FROM
- ADMIN_ALERT_NUMBER (e.g. +254748066116)
- ADMIN_PATH_TOKEN (e.g. 9fa83b27)
- ADMIN_SECRET (long secret used in X-ADMIN-SECRET header)
- ADMIN_USERNAME
- ADMIN_PASSWORD
- ADMIN_TOKEN_TTL (seconds; default 600)
"""

import os
import time
import secrets
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from fastapi import FastAPI, Request, Form, Header, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Optional: load .env in development
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

# Twilio (optional)
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

# ---- App ----
app = FastAPI(title="Mkoba Wallet Backend (with OTP & hidden admin)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Logging ----
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")

# ---- In-memory stores (swap to a real DB in production) ----
users: Dict[str, Dict[str, Any]] = {}          # username -> user dict
investments: Dict[str, Dict[str, Any]] = {}    # username -> pending investment dict
withdrawals: Dict[str, Dict[str, Any]] = {}    # username -> pending withdrawal dict
otps: Dict[str, Dict[str, Any]] = {}           # username -> {"otp": "123456", "expires_at": ts}

# ---- Config (env) ----
PLATFORM_NAME = os.getenv("PLATFORM_NAME", "Mkoba Wallet")
PAYMENT_NUMBER = os.getenv("PAYMENT_NUMBER", "0739075065")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin4857")

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin_static_token")  # legacy static token
ADMIN_TOKENS: Dict[str, float] = {}  # token -> issued_time (seconds)
ADMIN_TOKEN_TTL = int(os.getenv("ADMIN_TOKEN_TTL", "600"))

ADMIN_PATH_TOKEN = os.getenv("ADMIN_PATH_TOKEN", secrets.token_hex(4))  # short random if not provided
ADMIN_ROUTE_PREFIX = f"dev-{ADMIN_PATH_TOKEN}-panel"  # optional hidden path prefix
ADMIN_SECRET = os.getenv("ADMIN_SECRET", secrets.token_hex(12))  # header secret for dev access
ADMIN_ALERT_NUMBER = os.getenv("ADMIN_ALERT_NUMBER", None)

# Twilio
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")

# OTP config
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))  # 5 minutes

# ---- Models ----
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    referral: Optional[str] = None
    referred_users: List[str] = Field(default_factory=list)
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


# ---- Helpers ----
def hash_pwd(pw: str) -> str:
    import bcrypt

    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_pwd(pw: str, hashed: str) -> bool:
    import bcrypt

    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False


def send_sms(to_number: str, message: str):
    """
    Send SMS using Twilio if configured. Otherwise, log as a mock.
    This is server-side only; the user never learns about admin notifications via frontend.
    """
    if not (TWILIO_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM and TwilioClient):
        logger.info(f"[SMS MOCK] To: {to_number} | Message: {message}")
        return
    try:
        client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(body=message, from_=TWILIO_FROM, to=to_number)
        logger.info(f"Sent SMS to {to_number}")
    except Exception as e:
        logger.exception("Failed to send SMS: %s", e)


def generate_otp(length: int = OTP_LENGTH) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))


def store_otp_for_user(username: str, otp: str):
    otps[username] = {"otp": otp, "expires_at": time.time() + OTP_TTL_SECONDS}


def verify_otp_for_user(username: str, otp: str) -> bool:
    rec = otps.get(username)
    if not rec:
        return False
    if time.time() > rec["expires_at"]:
        otps.pop(username, None)
        return False
    if rec["otp"] == otp:
        otps.pop(username, None)
        return True
    return False


def prune_admin_tokens():
    now = time.time()
    expired = [t for t, ts in list(ADMIN_TOKENS.items()) if now - ts > ADMIN_TOKEN_TTL]
    for t in expired:
        ADMIN_TOKENS.pop(t, None)


def issue_admin_token() -> str:
    token = secrets.token_hex(16)
    ADMIN_TOKENS[token] = time.time()
    return token


# ---- Admin auth dependency (hides existence by returning 404) ----
def admin_auth(authorization: Optional[str] = Header(None), x_admin_secret: Optional[str] = Header(None)):
    """
    Accept either:
     - Authorization: Bearer <token> where token in ADMIN_TOKENS or token == ADMIN_TOKEN
     - OR X-ADMIN-SECRET header matching ADMIN_SECRET (developer)
    Otherwise raise 404 to hide endpoints.
    """
    # developer header first
    if x_admin_secret and x_admin_secret == ADMIN_SECRET:
        return True

    if not authorization or not authorization.startswith("Bearer "):
        # hide
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    token = authorization.split()[1]
    if token == ADMIN_TOKEN:
        return True
    prune_admin_tokens()
    if token in ADMIN_TOKENS:
        # optionally refresh TTL timestamp here if you want sliding expiry
        return True

    # hide existence
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# ---- Public endpoints ----
@app.get("/health")
def health():
    return {"status": "ok", "ts": time.time()}


@app.get("/platform/info")
def platform_info():
    return {"platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}


@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    referral: Optional[str] = Form(None),
):
    # allow ?ref=... on URL
    if not referral:
        referral = request.query_params.get("ref")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    pwd_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=pwd_hash,
        referral=referral,
    ).dict()

    # referral link
    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    # create OTP and send to user
    otp = generate_otp()
    store_otp_for_user(username, otp)
    user_msg = f"Your {PLATFORM_NAME} verification code is: {otp}. Expires in {OTP_TTL_SECONDS // 60} minutes."
    try:
        send_sms(number, user_msg)
    except Exception:
        logger.exception("Failed sending OTP to user %s", username)

    # server-side admin notification (private)
    try:
        admin_target = ADMIN_ALERT_NUMBER or PAYMENT_NUMBER
        admin_msg = f"New user registered: {username} ({number})"
        send_sms(admin_target, admin_msg)
    except Exception:
        logger.exception("Failed admin alert for %s", username)

    return {
        "message": f"User {username} registered. OTP sent to provided number.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER,
    }


@app.post("/verify-otp")
def verify_otp(username: str = Form(...), otp: str = Form(...)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if verify_otp_for_user(username, otp):
        u["approved"] = True
        return {"message": "OTP verified. Account approved."}
    raise HTTPException(status_code=400, detail="Invalid or expired OTP")


@app.post("/login")
async def login(request: Request):
    """
    Shared login: used by both user and admin frontends.
    If credentials match admin config, return is_admin=True + token.
    Otherwise authenticate normal user.
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

    # admin login
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = issue_admin_token()
        return {"message": "Admin login successful", "is_admin": True, "token": token, "username": ADMIN_USERNAME}

    # normal user login
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not yet approved")
    return {"message": f"Welcome {username}", "is_admin": False, "username": username, "is_approved": True}


@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    inv = investments.get(username)
    investment_amount = inv["amount"] if inv and inv.get("approved", False) else 0.0
    bonus_available = False
    bonus_message = "No bonus available"
    if inv and inv.get("approved", False):
        now = time.time()
        last = u.get("last_earning_time", 0)
        if u.get("bonus_days_remaining", 0) > 0 and (now - last) >= 86400:
            bonus_available = True
            bonus_message = f"Grab your daily 10% bonus! ({u['bonus_days_remaining']} days left)"
    return {
        "username": u["username"],
        "balance": u.get("balance", 0.0),
        "earnings": u.get("earnings", 0.0),
        "investment_amount": investment_amount,
        "bonus_available": bonus_available,
        "bonus_message": bonus_message,
        "approved": u.get("approved", False),
    }


@app.post("/invest")
async def invest(request: Request):
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

    investments[username] = Investment(
        username=username,
        amount=amount,
        transaction_ref=tx_ref or f"tx-{int(time.time())}",
        timestamp=datetime.now(),
    ).dict()

    return {"message": "Investment submitted. Pending approval.", "platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}


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
    u["balance"] = u.get("balance", 0.0) + bonus
    u["earnings"] = u.get("earnings", 0.0) + bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] = u.get("bonus_days_remaining", 0) - 1
    return {"message": f"Bonus KES {bonus:.2f} credited"}


# ---- Admin endpoints (protected & hidden via 404 on unauthorized) ----
# The admin endpoints are accessible if client provides:
#  - Authorization: Bearer <token> where token is valid issued admin token
#  OR
#  - X-ADMIN-SECRET header equals ADMIN_SECRET (developer secret)
#
# Unauthorized requests get 404 to hide endpoint existence.

# Helper to build responses appropriate to frontends expecting arrays
def _user_summary(u: Dict[str, Any]) -> Dict[str, Any]:
    # Return fields expected by the admin frontends
    username = u["username"]
    inv = investments.get(username, {})
    pending_withdrawal = withdrawals.get(username, {}).get("amount", 0.0) if username in withdrawals else 0.0
    return {
        "username": u["username"],
        "number": u["number"],
        "referral": u.get("referral"),
        "approved": u.get("approved", False),
        "total_invested": inv.get("amount", 0.0) if inv else 0.0,
        "investment_approved": inv.get("approved", False) if inv else False,
        "balance": u.get("balance", 0.0),
        "earnings": u.get("earnings", 0.0),
        "pending_withdrawal": pending_withdrawal,
    }


@app.get("/admin/users")
def admin_list_users(auth=Depends(admin_auth)):
    # return array to match frontend expectations
    return [ _user_summary(u) for u in users.values() ]


@app.post("/admin/approve_user")
def admin_approve_user(username: str = Form(...), auth=Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    u["approved"] = True
    return {"message": f"User {username} approved"}


@app.post("/admin/approve_investment")
def admin_approve_investment(username: str = Form(...), auth=Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    inv["approved"] = True
    u = users.get(username)
    if u:
        u["principal"] = u.get("principal", 0.0) + inv["amount"]
        u["bonus_days_remaining"] = 30  # example business rule
    return {"message": "Investment approved"}


@app.post("/admin/approve_withdrawal")
def admin_approve_withdrawal(username: str = Form(...), auth=Depends(admin_auth)):
    wd = withdrawals.get(username)
    if not wd:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    # process withdrawal: subtract from balance
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    amount = wd.get("amount", 0.0)
    if u.get("balance", 0.0) < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    u["balance"] = u.get("balance", 0.0) - amount
    wd["approved"] = True
    return {"message": f"Withdrawal of KES {amount:.2f} approved"}


@app.post("/admin/reset-password")
def admin_reset_password(target_username: str = Form(...), new_password: str = Form(...), auth=Depends(admin_auth)):
    u = users.get(target_username)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    u["password_hash"] = hash_pwd(new_password)
    return {"message": f"Password for {target_username} reset"}


@app.post("/admin/terminate_user")
def admin_terminate_user(username: str = Form(...), auth=Depends(admin_auth)):
    if username in users:
        users.pop(username, None)
    investments.pop(username, None)
    withdrawals.pop(username, None)
    return {"message": f"User {username} terminated"}


@app.get("/admin/validate")
def admin_validate(authorization: Optional[str] = Header(None), x_admin_secret: Optional[str] = Header(None)):
    # validate admin token or secret; returns 200 OK if valid (frontend expects ok)
    try:
        admin_auth(authorization=authorization, x_admin_secret=x_admin_secret)
        return {"valid": True}
    except HTTPException:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


@app.post("/admin/refresh")
def admin_refresh(authorization: Optional[str] = Header(None), x_admin_secret: Optional[str] = Header(None)):
    # exchange a valid token for a fresh one (return {"new_token": ...})
    # require existing token provided
    if x_admin_secret and x_admin_secret == ADMIN_SECRET:
        # developer header used - issue new token
        new = issue_admin_token()
        return {"new_token": new}
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    old = authorization.split()[1]
    prune_admin_tokens()
    if old == ADMIN_TOKEN:
        # static token used - issue new dynamic token
        new = issue_admin_token()
        return {"new_token": new}
    if old in ADMIN_TOKENS:
        # issue new token and remove old
        new = issue_admin_token()
        ADMIN_TOKENS.pop(old, None)
        return {"new_token": new}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# ---- Mirror admin endpoints under hidden developer prefix (optional) ----
# This is handy if you want to access admin APIs at a secret path like:
#   /dev-<ADMIN_PATH_TOKEN>-panel/users
# These simply reuse the same logic above, but having the version here can make it easier
# to access via the "secret admin path" frontend variant you designed.
# They also use the same admin_auth dependency so unauthorized requests still get 404.

@app.get(f"/{ADMIN_ROUTE_PREFIX}/users")
def hidden_admin_list_users(auth=Depends(admin_auth)):
    return admin_list_users(auth=auth)


@app.post(f"/{ADMIN_ROUTE_PREFIX}/approve_user")
def hidden_admin_approve_user(username: str = Form(...), auth=Depends(admin_auth)):
    return admin_approve_user(username=username, auth=auth)


@app.post(f"/{ADMIN_ROUTE_PREFIX}/approve_investment")
def hidden_admin_approve_investment(username: str = Form(...), auth=Depends(admin_auth)):
    return admin_approve_investment(username=username, auth=auth)


@app.post(f"/{ADMIN_ROUTE_PREFIX}/approve_withdrawal")
def hidden_admin_approve_withdrawal(username: str = Form(...), auth=Depends(admin_auth)):
    return admin_approve_withdrawal(username=username, auth=auth)


@app.post(f"/{ADMIN_ROUTE_PREFIX}/reset-password")
def hidden_admin_reset_password(target_username: str = Form(...), new_password: str = Form(...), auth=Depends(admin_auth)):
    return admin_reset_password(target_username=target_username, new_password=new_password, auth=auth)


@app.post(f"/{ADMIN_ROUTE_PREFIX}/terminate_user")
def hidden_admin_terminate_user(username: str = Form(...), auth=Depends(admin_auth)):
    return admin_terminate_user(username=username, auth=auth)


@app.get(f"/{ADMIN_ROUTE_PREFIX}/validate")
def hidden_admin_validate(authorization: Optional[str] = Header(None), x_admin_secret: Optional[str] = Header(None)):
    return admin_validate(authorization=authorization, x_admin_secret=x_admin_secret)


@app.post(f"/{ADMIN_ROUTE_PREFIX}/refresh")
def hidden_admin_refresh(authorization: Optional[str] = Header(None), x_admin_secret: Optional[str] = Header(None)):
    return admin_refresh(authorization=authorization, x_admin_secret=x_admin_secret)


# ---- Startup info (logging) ----
logger.info(f"Hidden admin route prefix: /{ADMIN_ROUTE_PREFIX}")
logger.info("Ensure ADMIN_PATH_TOKEN and ADMIN_SECRET are kept secret and not committed to source control.")
