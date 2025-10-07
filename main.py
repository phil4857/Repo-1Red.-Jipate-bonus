# main.py
"""
Full Mkoba Wallet Backend with:
- User registration + OTP
- Investment + withdrawal (withdrawal OTP)
- Bonus claiming
- Hidden admin endpoints with mirrored dev-secret path
- Admin notifications (Twilio or mock)
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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Logging ----
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mkoba-backend")

# ---- In-memory stores ----
users: Dict[str, Dict[str, Any]] = {}
investments: Dict[str, Dict[str, Any]] = {}
withdrawals: Dict[str, Dict[str, Any]] = {}
otps: Dict[str, Dict[str, Any]] = {}  # username -> {"otp": "123456", "expires_at": ts}

# ---- Config ----
PLATFORM_NAME = os.getenv("PLATFORM_NAME", "Mkoba Wallet")
PAYMENT_NUMBER = os.getenv("PAYMENT_NUMBER", "0739075065")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin4857")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin_static_token")
ADMIN_TOKENS: Dict[str, float] = {}
ADMIN_TOKEN_TTL = int(os.getenv("ADMIN_TOKEN_TTL", "600"))

ADMIN_PATH_TOKEN = os.getenv("ADMIN_PATH_TOKEN", secrets.token_hex(4))
ADMIN_ROUTE_PREFIX = f"dev-{ADMIN_PATH_TOKEN}-panel"
ADMIN_SECRET = os.getenv("ADMIN_SECRET", secrets.token_hex(12))
ADMIN_ALERT_NUMBER = os.getenv("ADMIN_ALERT_NUMBER", None)

TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")

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

class Withdrawal(BaseModel):
    username: str
    amount: float
    otp_verified: bool = False
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
    if not rec: return False
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

def admin_auth(authorization: Optional[str] = Header(None), x_admin_secret: Optional[str] = Header(None)):
    if x_admin_secret and x_admin_secret == ADMIN_SECRET:
        return True
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    token = authorization.split()[1]
    if token == ADMIN_TOKEN: return True
    prune_admin_tokens()
    if token in ADMIN_TOKENS: return True
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

def _user_summary(u: Dict[str, Any]) -> Dict[str, Any]:
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

# ---- Public Endpoints ----
@app.get("/health")
def health():
    return {"status": "ok", "ts": time.time()}

@app.get("/platform/info")
def platform_info():
    return {"platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}

@app.post("/register")
async def register(request: Request, username: str = Form(...), number: str = Form(...),
                   password: str = Form(...), referral: Optional[str] = Form(None)):
    if not referral:
        referral = request.query_params.get("ref")
    if username in users:
        raise HTTPException(status_code=400, detail="Username exists")
    pwd_hash = hash_pwd(password)
    users[username] = User(username=username, number=number, password_hash=pwd_hash, referral=referral).dict()
    if referral and referral in users:
        users[referral]["referred_users"].append(username)
    otp = generate_otp()
    store_otp_for_user(username, otp)
    send_sms(number, f"Your {PLATFORM_NAME} OTP: {otp}")
    admin_target = ADMIN_ALERT_NUMBER or PAYMENT_NUMBER
    send_sms(admin_target, f"New user registered: {username} ({number})")
    return {"message": f"User {username} registered. OTP sent.", "platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}

@app.post("/verify-otp")
def verify_otp(username: str = Form(...), otp: str = Form(...)):
    u = users.get(username)
    if not u: raise HTTPException(status_code=404, detail="User not found")
    if verify_otp_for_user(username, otp):
        u["approved"] = True
        return {"message": "OTP verified. Account approved."}
    raise HTTPException(status_code=400, detail="Invalid or expired OTP")

@app.post("/login")
async def login(request: Request):
    content_type = (request.headers.get("content-type") or "")
    if "application/json" in content_type: data = await request.json()
    else: data = dict(await request.form())
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing username/password")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = issue_admin_token()
        return {"message": "Admin login successful", "is_admin": True, "token": token, "username": ADMIN_USERNAME}
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not yet approved")
    return {"message": f"Welcome {username}", "is_admin": False, "username": username, "is_approved": True}

@app.get("/dashboard")
def dashboard(username: str):
    u = users.get(username)
    if not u: raise HTTPException(status_code=404, detail="User not found")
    inv = investments.get(username)
    investment_amount = inv["amount"] if inv and inv.get("approved", False) else 0.0
    bonus_available = False
    bonus_message = "No bonus available"
    if inv and inv.get("approved", False):
        now = time.time()
        last = u.get("last_earning_time", 0)
        if u.get("bonus_days_remaining", 0) > 0 and (now - last) >= 86400:
            bonus_available = True
            bonus_message = f"Grab daily 10% bonus ({u['bonus_days_remaining']} days left)"
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
    try: amount = float(amount)
    except: raise HTTPException(status_code=400, detail="Invalid amount")
    if amount < 500: raise HTTPException(status_code=400, detail="Minimum investment is KES 500")
    u = users.get(username)
    if not u or not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not approved")
    investments[username] = Investment(username=username, amount=amount,
                                       transaction_ref=tx_ref or f"tx-{int(time.time())}",
                                       timestamp=datetime.now()).dict()
    return {"message": "Investment submitted. Pending approval.", "platform": PLATFORM_NAME, "payment_number": PAYMENT_NUMBER}

@app.post("/withdraw/request")
async def request_withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    if not u or not u.get("approved", False):
        raise HTTPException(status_code=403, detail="Account not approved")
    if amount <= 0 or amount > u.get("balance", 0):
        raise HTTPException(status_code=400, detail="Invalid amount")
    otp = generate_otp()
    store_otp_for_user(username + "_withdraw", otp)
    withdrawals[username] = Withdrawal(username=username, amount=amount).dict()
    send_sms(u["number"], f"Your withdrawal OTP is {otp}")
    send_sms(ADMIN_ALERT_NUMBER or PAYMENT_NUMBER, f"User {username} requested withdrawal {amount} KES")
    return {"message": f"OTP sent to {u['number']}. Confirm withdrawal to proceed."}

@app.post("/withdraw/verify")
def verify_withdraw(username: str = Form(...), otp: str = Form(...)):
    key = username + "_withdraw"
    wd = withdrawals.get(username)
    if not wd: raise HTTPException(status_code=404, detail="No pending withdrawal")
    if verify_otp_for_user(key, otp):
        wd["otp_verified"] = True
        return {"message": f"Withdrawal OTP verified for {username}"}
    raise HTTPException(status_code=400, detail="Invalid or expired OTP")

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
    u["balance"] += bonus
    u["earnings"] += bonus
    u["last_earning_time"] = now
    u["bonus_days_remaining"] -= 1
    return {"message": f"Bonus KES {bonus:.2f} credited"}

# ---- Admin Endpoints ----
@app.get("/admin/users")
def admin_list_users(auth=Depends(admin_auth)):
    return [_user_summary(u) for u in users.values()]

@app.post("/admin/approve_user")
def admin_approve_user(username: str = Form(...), auth=Depends(admin_auth)):
    u = users.get(username)
    if not u: raise HTTPException(status_code=404, detail="Not Found")
    u["approved"] = True
    return {"message": f"User {username} approved"}

@app.post("/admin/approve_investment")
def admin_approve_investment(username: str = Form(...), auth=Depends(admin_auth)):
    inv = investments.get(username)
    if not inv: raise HTTPException(status_code=404, detail="Not Found")
    inv["approved"] = True
    u = users.get(username)
    if u:
        u["principal"] += inv["amount"]
        u["bonus_days_remaining"] = 30
    return {"message": "Investment approved"}

@app.post("/admin/approve_withdrawal")
def admin_approve_withdrawal(username: str = Form(...), auth=Depends(admin_auth)):
    wd = withdrawals.get(username)
    if not wd or not wd.get("otp_verified", False):
        raise HTTPException(status_code=400, detail="Withdrawal not verified")
    u = users.get(username)
    if not u: raise HTTPException(status_code=404, detail="Not Found")
    amount = wd.get("amount", 0.0)
    if u["balance"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    u["balance"] -= amount
    wd["approved"] = True
    return {"message": f"Withdrawal of KES {amount:.2f} approved"}

# Admin hidden route mirrors
@app.get(f"/{ADMIN_ROUTE_PREFIX}/users")
def hidden_admin_list_users(auth=Depends(admin_auth)):
    return admin_list_users(auth=auth)
# Similarly, mirror all other admin endpoints under /dev-<ADMIN_PATH_TOKEN>-panel/* using the same approach

# ---- Startup info ----
logger.info(f"Hidden admin route prefix: /{ADMIN_ROUTE_PREFIX}")
logger.info("Keep ADMIN_PATH_TOKEN and ADMIN_SECRET secret!")
