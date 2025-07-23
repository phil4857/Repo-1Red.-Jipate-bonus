from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import bcrypt
import json
import os

router = APIRouter()

# Path to your data.json file
DATA_FILE = "data.json"

class LoginRequest(BaseModel):
    username: str
    password: str

def load_users():
    if not os.path.exists(DATA_FILE):
        raise HTTPException(status_code=500, detail="User database not found")

    with open(DATA_FILE, "r") as f:
        try:
            data = json.load(f)
            return data.get("users", [])
        except json.JSONDecodeError:
            raise HTTPException(status_code=500, detail="Corrupted user database")

@router.post("/login")
def admin_login(data: LoginRequest):
    users = load_users()
    user = next((u for u in users if u["username"] == data.username), None)

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # bcrypt password check
    if not bcrypt.checkpw(data.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Incorrect password")

    # check admin flag
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Access denied. Not an admin.")

    return {
        "message": "Admin login successful",
        "username": data.username,
        "is_admin": True
    }
