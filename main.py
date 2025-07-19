from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import bcrypt

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can restrict this to your Vercel domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory data store (use a real DB in production)
users = {
    "admin": {
        "username": "admin",
        "password_hash": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(),
        "approved": True,
        "number": "",
        "referral": None,
        "balance": 0
    }
}

@app.post("/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    number: str = Form(...),
    referral: str = Form(None)
):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists.")
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users[username] = {
        "username": username,
        "password_hash": password_hash,
        "approved": False,
        "number": number,
        "referral": referral,
        "balance": 0
    }
    return {"message": "Registration successful. Wait for admin approval."}


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    if not user["approved"]:
        raise HTTPException(status_code=403, detail="User not approved by admin.")

    return {"message": "Login successful."}


@app.get("/admin/view_users")
def view_users():
    return users


@app.post("/admin/approve_user")
def approve_user(username: str = Form(...), admin_password: str = Form(...)):
    admin = users.get("admin")
    if not admin or not bcrypt.checkpw(admin_password.encode(), admin["password_hash"].encode()):
        raise HTTPException(status_code=403, detail="Admin authentication failed.")

    if username not in users:
        raise HTTPException(status_code=404, detail="User not found.")

    users[username]["approved"] = True
    return {"message": f"User '{username}' approved successfully."}
