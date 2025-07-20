from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt, time

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://jipate-bonus-v1-bcti.vercel.app", "https://*.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {}
investments = {}
login_attempts = {}

class User(BaseModel):
    username: str
    password_hash: str
    approved: bool = False
    referral: str = None
    referred_users: list = []
    balance: float = 0.0
    earnings: float = 0.0
    last_earning_time: float = time.time()

class Investment(BaseModel):
    username: str
    amount: float
    transaction_ref: str
    approved: bool = False
    timestamp: datetime

def hash_pwd(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pwd(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

@app.get("/")
def root(): return {"message": "Welcome to Jipate Bonus Investment Platform"}

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), confirm: str = Form(...), referral: str = Form(None)):
    if password != confirm: raise HTTPException(400, "Passwords don’t match")
    if username in users: raise HTTPException(400, "Username exists")
    h = hash_pwd(password)
    users[username] = User(username=username, password_hash=h, referral=referral).dict()
    if referral in users: users[referral]["referred_users"].append(username)
    return {"message": "Registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    u = users.get(username)
    if not u or not check_pwd(password, u["password_hash"]):
        c = login_attempts.setdefault(username, 0) + 1
        login_attempts[username] = c
        if c >= 3: raise HTTPException(403, "Account locked. Contact admin.")
        raise HTTPException(401, "Invalid credentials")
    if not u["approved"]: raise HTTPException(403, "Awaiting admin approval")
    login_attempts[username] = 0
    return {"message": f"Welcome {username}"}

@app.post("/invest")
def invest(username: str = Form(...), amount: float = Form(...), transaction_ref: str = Form(...)):
    u = users.get(username)
    if not u: raise HTTPException(404, "User not found")
    if not u["approved"]: raise HTTPException(403, "Not approved")
    if username in investments: raise HTTPException(400, "Already invested")
    amt = amount * (0.95 if datetime.utcnow().strftime("%A") == "Sunday" else 1)
    investments[username] = Investment(username=username, amount=amt, transaction_ref=transaction_ref, timestamp=datetime.utcnow()).dict()
    note = "Send to MPESA 0737734533"
    return {"message": f"Invested KES{amt:.2f}. {note}"}

@app.post("/admin/approve_user")
def approve_user(username: str = Form(...)):
    u = users.get(username)
    if not u: raise HTTPException(404, "No such user")
    u["approved"] = True
    return {"message": f"{username} approved"}

@app.post("/admin/approve_investment")
def approve_investment(username: str = Form(...)):
    inv = investments.get(username)
    if not inv: raise HTTPException(404, "No invest found")
    if inv["approved"]: return {"message": "Already approved"}
    inv["approved"] = True
    users[username]["balance"] += inv["amount"]
    ref = users[username]["referral"]
    if ref in users: users[ref]["balance"] += inv["amount"] * 0.05
    return {"message": f"{username} investment approved"}

@app.post("/earnings/daily")
def daily():
    now = time.time(); count = 0
    for u, inv in investments.items():
        if inv["approved"] and now - users[u]["last_earning_time"] >= 86400:
            e = inv["amount"] * 0.10
            users[u]["earnings"] += e
            users[u]["balance"] += e
            users[u]["last_earning_time"] = now
            count += 1
    return {"message": f"Daily earnings added for {count}"}

@app.post("/withdraw")
def withdraw(username: str = Form(...), amount: float = Form(...)):
    u = users.get(username)
    inv = investments.get(username)
    if not u or not inv: raise HTTPException(404, "No account or investment")
    invested = inv["amount"]; balance = u["balance"]
    limit = 150 if invested < 1000 else (300 if invested < 1500 else invested * 0.3)
    if amount > limit: raise HTTPException(400, f"Limit is {limit}")
    if amount > balance: raise HTTPException(400, "Insufficient funds")
    u["balance"] -= amount
    return {"message": f"Requested withdrawal of {amount}. Await confirmation."}

@app.get("/admin/view_users")
def view_users(): return users

@app.get("/admin/view_investments")
def view_investments(): return investments
