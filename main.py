from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from passlib.hash import bcrypt
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your Vercel URL for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fake DB
users = {
    "admin": {
        "username": "admin",
        "password_hash": bcrypt.hash("admin123"),
        "number": "0000000000",
        "balance": 0,
        "approved": True,
        "referral": None
    }
}

@app.post("/register")
async def register(
    username: str = Form(...),
    number: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    users[username] = {
        "username": username,
        "number": number,
        "password_hash": bcrypt.hash(password),
        "balance": 0,
        "approved": False,
        "referral": None
    }
    return {"message": "User registered successfully"}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not bcrypt.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="Account not approved yet")
    return {"message": "Login successful"}

@app.get("/admin/view_users")
async def view_users():
    return users
