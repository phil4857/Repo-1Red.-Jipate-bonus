# main.py
"""
FastAPI app with:
 - User registration + Twilio OTP verification
 - Private server-side admin SMS alert on registration
 - Hidden developer/admin route (path comes from ADMIN_PATH_TOKEN) - returns 404 to outsiders
 - Admin endpoints protected by ADMIN_SECRET header or admin tokens, but always return 404 on unauthorized access
 - In-memory storage (same approach you had previously). Swap to a DB in production.

Environment variables expected:
 - TWILIO_SID
 - TWILIO_AUTH_TOKEN
 - TWILIO_FROM    (E.164 like +1XXXXXXXXXX)
 - ADMIN_ALERT_NUMBER  (E.164, e.g. +254748066116)
 - ADMIN_PATH_TOKEN    (e.g. 9fa83b27)  => dev route becomes /dev-9fa83b27-panel
 - ADMIN_SECRET        (string used in X-ADMIN-SECRET header to view the dev admin)
 - ADMIN_USERNAME
 - ADMIN_PASSWORD
 - ADMIN_TOKEN_TTL (seconds, optional; default 600)
"""

from fastapi import FastAPI, Form, HTTPException, Depends, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import bcrypt, time, secrets, os, logging

# Optional: load .env in development (pip install python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Twilio
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None  # If Twilio not installed, SMS sending will be a no-op but logged.

# ----- App setup -----
app = FastAPI(title="Mkoba Wallet - Backend (with OTP & hidden admin)")

# CORS - allow all during testing; restrict in prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- In-memory storage -----
users: Dict[str, Dict[str, Any]] = {}            # username -> User dict
investments: Dict[str, Dict[str, Any]] = {}      # username -> pending Investment dict
withdrawals: Dict[str, Dict[str, Any]] = {}      # username -> WithdrawalRequest dict
otps: Dict[str, Dict[str, Any]] = {}             # username -> {"otp": "123456", "expires_at": timestamp}

# ----- Platform config -----
PLATFORM_NAME = os.getenv("PLATFORM_NAME", "Mkoba Wallet")
PAYMENT_NUMBER = os.getenv("PAYMENT_NUMBER", "0739075065")

# ----- Admin config -----
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin4857")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin_static_token")  # legacy static (kept for compatibility)

ADMIN_TOKENS: Dict[str, float] = {}  # token -> issued_time
ADMIN_TOKEN_TTL = int(os.getenv("ADMIN_TOKEN_TTL", "600"))  # seconds

ADMIN_PATH_TOKEN = os.getenv("ADMIN_PATH_TOKEN", secrets.token_hex(4))  # short random if not provided
# Dev/admin path is: /dev-<ADMIN_PATH_TOKEN>-panel
ADMIN_ROUTE_PREFIX = f"dev-{ADMIN_PATH_TOKEN}-panel"  # used to create hidden dev/admin endpoints

ADMIN_SECRET = os.getenv("ADMIN_SECRET", secrets.token_hex(12))  # header secret required to see the dev panel
ADMIN_ALERT_NUMBER = os.getenv("ADMIN_ALERT_NUMBER", None)  # e.g. +254748066116

# Twilio config
TWILIO_SID = os.getenv("TWILIO_SID", None)
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", None)
TWILIO_FROM = os.getenv("TWILIO_FROM", None)  # E.164 format, e.g. +1xxx

# OTP config
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))  # 5 minutes

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")


# ----- Models -----
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


# ----- Utilities -----
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
    expired = [t for t, ts in list(ADMIN_TOKENS.items()) if now - ts > ADMIN_TOKEN_TTL]
    for t in expired:
        ADMIN_TOKENS.pop(t, None)


def send_sms(to_number: str, message: str):
    """
    Sends an SMS via Twilio if configured. Otherwise logs it.
    This function is server-side only; nothing is returned to the user that indicates an admin notification was sent.
    """
    if not (TWILIO_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM and TwilioClient):
        logger.info(f"[SMS MOCK] To: {to_number} | Message: {message}")
        return

    try:
        client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
        # Twilio expects E.164 phone numbers
        client.messages.create(body=message, from_=TWILIO_FROM, to=to_number)
        logger.info(f"SMS sent to {to_number}")
    except Exception as e:
        logger.exception(f"Failed to send SMS to {to_number}: {e}")


def generate_otp(length: int = OTP_LENGTH) -> str:
    """Generate a numeric OTP of given length."""
    return "".join(secrets.choice("0123456789") for _ in range(length))


def store_otp_for_user(username: str, otp: str):
    expires_at = time.time() + OTP_TTL_SECONDS
    otps[username] = {"otp": otp, "expires_at": expires_at}
    logger.debug(f"Stored OTP for {username}, expires_at={expires_at}")


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


def notify_admin_of_registration(username: str, number: str):
    """Server-side admin notification on registration. Not exposed to users."""
    admin_number = ADMIN_ALERT_NUMBER or PAYMENT_NUMBER
    if not admin_number:
        logger.info("No ADMIN_ALERT_NUMBER configured; skipping admin notification.")
        return
    msg = f"New user registered: {username} ({number})"
    try:
        send_sms(admin_number, msg)
    except Exception as e:
        logger.exception("Failed to send admin registration SMS: %s", e)


# ----- Hidden admin auth dependency -----
def admin_auth(x_admin_secret: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    """
    Admin auth dependency for hidden admin endpoints.
    IMPORTANT: To keep admin routes invisible, unauthorized requests get a 404 (Not Found) rather than 401/403.
    Valid access methods:
      - Include header X-ADMIN-SECRET matching ADMIN_SECRET (developer secret)
      - OR include Authorization: Bearer <token> where token is in ADMIN_TOKENS and not expired
    """
    # Accept developer secret header first
    if x_admin_secret and x_admin_secret == ADMIN_SECRET:
        return True

    # Try bearer token
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split()[1]
        # static token allowed
        if token == ADMIN_TOKEN:
            return True
        prune_admin_tokens()
        if token in ADMIN_TOKENS:
            return True

    # To hide admin existence, return 404 for unauthorized
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# ----- Basic routes -----
@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time()}


@app.get("/platform/info")
def platform_info():
    return {"platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}


# ----- User routes -----
@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    referral: Optional[str] = Form(None),
):
    """
    Register a user. Immediately triggers OTP SMS to the user's phone and a private admin alert SMS.
    The user must then call /verify-otp to activate (approved=True).
    """
    # referral via query param also allowed
    if not referral:
        referral = request.query_params.get("ref")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    pw_hash = hash_pwd(password)
    users[username] = User(
        username=username,
        number=number,
        password_hash=pw_hash,
        referral=referral,
    ).dict()

    # Add referral relationship
    if referral and referral in users:
        users[referral]["referred_users"].append(username)

    # Generate and send OTP to user
    otp = generate_otp()
    store_otp_for_user(username, otp)
    user_msg = f"Your {PLATFORM_NAME} verification code is: {otp}. It expires in {OTP_TTL_SECONDS // 60} minutes."
    try:
        send_sms(number, user_msg)
    except Exception as e:
        logger.exception("Failed to send OTP SMS to user %s: %s", username, e)

    # Private admin notification (server-side only)
    try:
        notify_admin_of_registration(username, number)
    except Exception:
        logger.exception("Admin notification failed for %s", username)

    # Return generic response (no hint of admin notification)
    return {
        "message": f"User {username} registered. An OTP was sent to the provided number.",
        "platform": PLATFORM_NAME,
        "payment_number": PAYMENT_NUMBER,
    }


@app.post("/verify-otp")
def verify_otp(username: str = Form(...), otp: str = Form(...)):
    """
    Verify OTP for a username. If valid, mark user.approved = True so they can start earning/investing.
    """
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if verify_otp_for_user(username, otp):
        u["approved"] = True
        return {"message": "OTP verified. Account approved.", "username": username}
    raise HTTPException(status_code=400, detail="Invalid or expired OTP")


@app.post("/login")
async def login(request: Request):
    """
    Shared login endpoint for users.
    Admin login is available only via the hidden dev admin login endpoint (below).
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
        "username": username,
    }


@app.get("/user/{username}")
def get_user(username: str):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
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
        "last_earning_time": u.get("last_earning_time", 0),
    }


@app.post("/invest")
async def invest(request: Request):
    """
    Create a pending investment. Admin must approve later (admin approves via hidden panel).
    This keeps your original flow: do NOT move principal here.
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
    u["balance"] = u.get("balance", 0.0) + bonus
    u["earnings"] = u.get("earnings", 0.0) + bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] = u.get("bonus_days_remaining", 0) - 1

    return {"message": f"Bonus KES {bonus:.2f} credited"}


# ----- Hidden developer/admin routes -----
# These endpoints are intentionally *not* exposed anywhere in the user UI.
# Unauthorized access returns 404 to hide their existence.

# Admin root / developer panel (hidden)
@app.get(f"/{ADMIN_ROUTE_PREFIX}")
def dev_admin_panel(x_admin_secret: Optional[str] = Header(None)):
    """
    Very small dev panel entry to check if you have developer access.
    This endpoint only checks the X-ADMIN-SECRET header; otherwise returns 404.
    """
    if x_admin_secret != ADMIN_SECRET:
        # Hide existence
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return {"status": "ok", "message": "Developer admin access granted.", "admin_route": ADMIN_ROUTE_PREFIX}


# Admin login - only via hidden path and requires developer header to reach it
@app.post(f"/{ADMIN_ROUTE_PREFIX}/login")
def admin_login(request: Request, x_admin_secret: Optional[str] = Header(None)):
    """
    Admin login through the hidden route. Must include X-ADMIN-SECRET header.
    Returns a dynamic bearer token for further admin calls.
    """
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    content_type = (request.headers.get("content-type") or "")
    data = {}
    if "application/json" in content_type:
        # admin should send JSON credentials
        data = request.json()  # will be a coroutine if not awaited; do simple form handling instead
        # to simplify usage for many clients, prefer form-based below
    form = None
    try:
        form = request._body  # fallback - don't rely on this; prefer sending form data
    except Exception:
        form = None

    # Simpler: parse as form if any
    try:
        form = await request.form()
        data = dict(form)
    except Exception:
        # maybe JSON - try again safely
        try:
            data = request.json()
            if hasattr(data, "__await__"):
                data = await data
        except Exception:
            data = {}

    username = data.get("username")
    password = data.get("password")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = secrets.token_hex(16)
        ADMIN_TOKENS[token] = time.time()
        return {"message": "Admin login successful", "token": token}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# Admin: list users (hidden)
@app.get(f"/{ADMIN_ROUTE_PREFIX}/users")
def admin_list_users(auth=Depends(admin_auth)):
    # Return summary of users
    return {"count": len(users), "users": [{ "username": u["username"], "number": u["number"], "approved": u["approved"] } for u in users.values()]}


# Admin: get single user (hidden)
@app.get(f"/{ADMIN_ROUTE_PREFIX}/user/{username}")
def admin_get_user(username: str, auth=Depends(admin_auth)):
    u = users.get(username)
    if not u:
        # Hide existence for non-admin probing
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return u


# Admin: approve investment (hidden)
@app.post(f"/{ADMIN_ROUTE_PREFIX}/investment/approve")
def admin_approve_investment(username: str = Form(...), auth=Depends(admin_auth)):
    inv = investments.get(username)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    inv["approved"] = True
    # move principal into user's principal
    u = users.get(username)
    if u:
        u["principal"] = u.get("principal", 0.0) + inv["amount"]
        # example: set bonus days if your business logic requires it
        u["bonus_days_remaining"] = 30
    return {"message": "Investment approved"}


# Admin: approve user (hidden)
@app.post(f"/{ADMIN_ROUTE_PREFIX}/user/approve")
def admin_approve_user(username: str = Form(...), auth=Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    u["approved"] = True
    return {"message": f"User {username} approved"}


# Admin: resend OTP to user (hidden)
@app.post(f"/{ADMIN_ROUTE_PREFIX}/user/resend-otp")
def admin_resend_otp(username: str = Form(...), auth=Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    otp = generate_otp()
    store_otp_for_user(username, otp)
    user_msg = f"Your {PLATFORM_NAME} verification code is: {otp}. It expires in {OTP_TTL_SECONDS // 60} minutes."
    send_sms(u["number"], user_msg)
    return {"message": "OTP resent"}


# Admin: revoke user approval (hidden)
@app.post(f"/{ADMIN_ROUTE_PREFIX}/user/revoke")
def admin_revoke_user(username: str = Form(...), auth=Depends(admin_auth)):
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    u["approved"] = False
    return {"message": f"User {username} revoked"}


# Admin: view pending investments (hidden)
@app.get(f"/{ADMIN_ROUTE_PREFIX}/investments/pending")
def admin_pending_investments(auth=Depends(admin_auth)):
    pending = [inv for inv in investments.values() if not inv.get("approved", False)]
    return {"pending_count": len(pending), "pending": pending}


# ----- NOTE on admin route secrecy -----
# - The admin route path is /dev-<ADMIN_PATH_TOKEN>-panel, where ADMIN_PATH_TOKEN is set via env var ADMIN_PATH_TOKEN.
# - To query it, include header: X-ADMIN-SECRET: <ADMIN_SECRET>
# - Unauthorized requests get a 404 to hide admin endpoints.
# - ADMIN_SECRET and ADMIN_PATH_TOKEN should be stored securely (not in public source).
#
# Example .env:
# TWILIO_SID=ACxxxxxxxxxxxxxxxxxxx
# TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxx
# TWILIO_FROM=+1XXXXXXXXXX
# ADMIN_ALERT_NUMBER=+254748066116
# ADMIN_PATH_TOKEN=9fa83b27
# ADMIN_SECRET=superstrongsecret
# ADMIN_USERNAME=admin
# ADMIN_PASSWORD=admin4857

# ----- Small startup log to show admin route (only in server logs) -----
logger.info(f"Hidden admin route available at: /{ADMIN_ROUTE_PREFIX} (requires X-ADMIN-SECRET header).")
logger.info("Ensure ADMIN_PATH_TOKEN and ADMIN_SECRET are kept secret and not in public code.")
