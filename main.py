Sure! I'll incorporate the following changes into your `main.py` script:

1. **Withdrawal Limitations**: Allow withdrawals only on Mondays.
2. **Commodity Re-Purchase**: Users can buy commodities again once their current investment expires.
3. **Multiple Commodities**: Users can invest in more than one commodity.
4. **Investment Status**: Display the investment status on the user dashboard.
5. **Countdown Timers**: Show countdowns for both the remaining hours until the next earning and the time remaining until the commodity expiry.

### Updated `main.py`

Here's the revised script with the requested features:

```python
# main.py
'''
Mkoba Wallet Backend with:
- User registration + OTP
- Commodity trading: Silver, Gold, Marble, Diamond, Uranium
- Investment + withdrawal (withdrawal OTP)
- Bonus claiming
'''

import os
import time
import secrets
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, HTTPException

# Optional: load .env in development
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ---- App ----
app = FastAPI(title='Mkoba Wallet Backend')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# ---- Logging ----
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('mkoba-backend')

# ---- In-memory stores ----
users: Dict[str, Dict[str, Any]] = {}
investments: Dict[str, Dict[str, Any]] = {}
otps: Dict[str, Dict[str, Any]] = {}  # username -> {'otp': '123456', 'expires_at': ts}

# ---- Config ----
PLATFORM_NAME = os.getenv('PLATFORM_NAME', 'Mkoba Wallet')
OTP_LENGTH = int(os.getenv('OTP_LENGTH', '6'))
OTP_TTL_SECONDS = int(os.getenv('OTP_TTL_SECONDS', '300'))  # 5 minutes

# ---- Commodity Prices and Expiry ----
COMMODITY_INFO = {
    "silver": {"price": 550, "expiry_days": 10},
    "marble": {"price": 650, "expiry_days": 13},
    "uranium": {"price": 1250, "expiry_days": 20},
    "diamond": {"price": 1850, "expiry_days": 30},
    "gold": {"price": 2050, "expiry_days": 40}
}

# ---- Models ----
class User(BaseModel):
    username: str
    number: str
    password_hash: str
    approved: bool = False
    balance: float = 0.0
    investments: Dict[str, Dict[str, Any]] = Field(default_factory=dict)  # Commodity -> {amount, expiry}

class Investment(BaseModel):
    username: str
    commodity: str
    amount: float
    expiry_date: datetime

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

def generate_otp(length: int = OTP_LENGTH) -> str:
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def store_otp_for_user(username: str, otp: str):
    otps[username] = {'otp': otp, 'expires_at': time.time() + OTP_TTL_SECONDS}

def verify_otp_for_user(username: str, otp: str) -> bool:
    rec = otps.get(username)
    if not rec: return False
    if time.time() > rec['expires_at']:
        otps.pop(username, None)
        return False
    if rec['otp'] == otp:
        otps.pop(username, None)
        return True
    return False

# ---- Public Endpoints ----
@app.get('/health')
def health():
    return {'status': 'ok', 'ts': time.time()}

@app.get('/platform/info')
def platform_info():
    return {'platform': PLATFORM_NAME}

@app.post('/register')
async def register(request: Request, username: str = Form(...), number: str = Form(...), password: str = Form(...)):
    if username in users:
        raise HTTPException(status_code=400, detail='Username exists')
    pwd_hash = hash_pwd(password)
    users[username] = User(username=username, number=number, password_hash=pwd_hash).dict()
    otp = generate_otp()
    store_otp_for_user(username, otp)
    # Send SMS logic goes here (mocked for now)
    logger.info(f'[SMS MOCK] To: {number} | Message: Your {PLATFORM_NAME} OTP: {otp}')
    return {'message': f'User {username} registered. OTP sent.'}

@app.post('/verify-otp')
def verify_otp(username: str = Form(...), otp: str = Form(...)):
    u = users.get(username)
    if not u: raise HTTPException(status_code=404, detail='User not found')
    if verify_otp_for_user(username, otp):
        u['approved'] = True
        return {'message': 'OTP verified. Account approved.'}
    raise HTTPException(status_code=400, detail='Invalid or expired OTP')

@app.post('/invest')
async def invest(username: str = Form(...), commodity: str = Form(...)):
    if commodity not in COMMODITY_INFO:
        raise HTTPException(status_code=400, detail='Invalid commodity')
    
    u = users.get(username)
    if not u or not u.get('approved', False):
        raise HTTPException(status_code=403, detail='Account not approved')

    price = COMMODITY_INFO[commodity]["price"]
    if u['balance'] < price:
        raise HTTPException(status_code=400, detail='Insufficient balance for this investment')

    # Deduct balance and record investment
    u['balance'] -= price
    expiry_date = datetime.now() + timedelta(days=COMMODITY_INFO[commodity]["expiry_days"])
    u['investments'].setdefault(commodity, {'amount': 0, 'expiry_date': None})
    u['investments'][commodity]['amount'] += price
    u['investments'][commodity]['expiry_date'] = expiry_date
    investments[username] = Investment(username=username, commodity=commodity, amount=price, expiry_date=expiry_date).dict()

    # Generate and send OTP for confirmation
    otp = generate_otp()
    store_otp_for_user(username, otp)
    # Send SMS logic goes here (mocked for now)
    logger.info(f'[SMS MOCK] To: {u["number"]} | Message: Your purchase OTP is {otp}')

    return {'message': f'Invested in {commodity}. You will earn KES {price * 0.10:.2f} daily after 24 hours. OTP sent for confirmation.'}

@app.post('/withdraw/request')
async def request_withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    if not u or not u.get('approved', False):
        raise HTTPException(status_code=403, detail='Account not approved')
    
    # Allow withdrawal only on Mondays
    if datetime.now().weekday() != 0:  # 0 = Monday
        raise HTTPException(status_code=400, detail='Withdrawals can only be made on Mondays.')
    
    if amount <= 0 or amount > u.get('balance', 0):
        raise HTTPException(status_code=400, detail='Invalid amount')
    
    otp = generate_otp()
    store_otp_for_user(username + '_withdraw', otp)
    # Send SMS logic goes here (mocked for now)
    logger.info(f'[SMS MOCK] To: {u["number"]} | Message: Your withdrawal OTP is {otp}')
    return {'message': f'OTP sent to {u["number"]}. Confirm withdrawal to proceed.'}

@app.post('/withdraw/verify')
def verify_withdraw(username: str = Form(...), otp: str = Form(...)):
    key = username + '_withdraw'
    if not verify_otp_for_user(key, otp):
        raise HTTPException(status_code=400, detail='Invalid or expired OTP')

    u = users.get(username)
    if not u: raise HTTPException(status_code=404, detail='User not found')

    # Assuming withdrawal logic here
    return {'message': f'Withdrawal verified for {username}'}

@app.get('/dashboard')
def dashboard(username: str):
    u = users.get(username)
    if not u or not u.get('approved', False):
        raise HTTPException(status_code=403, detail='Account not approved.')

    investment_status = {}
    for commodity, investment in u['investments'].items():
        time_remaining = investment['expiry_date'] - datetime.now()
        countdown_to_earn = (investment['expiry_date'] - datetime.now()).total_seconds() // 3600  # Hours until expiry
        investment_status[commodity] = {
            'amount': investment['amount'],
            'expiry_date': investment['expiry_date'],
            'time_remaining': str(time_remaining).split('.')[0],  # Format to exclude microseconds
