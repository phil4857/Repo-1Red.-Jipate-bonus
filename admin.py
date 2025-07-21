from fastapi import APIRouter, HTTPException, Form, Query
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Dict
import json
import os

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
INVESTMENTS_FILE = os.path.join(BASE_DIR, "data", "investments.json")

def read_data(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

def write_data(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

@router.get("/admin/view_users")
def view_users(admin_password: str = Query(...)):
    users = read_data(USERS_FILE)
    admin = users.get("admin")
    if not admin or not pwd_context.verify(admin_password, admin["password_hash"]):
        raise HTTPException(status_code=403, detail="Unauthorized access")
    return users

@router.get("/admin/view_investments")
def view_investments(admin_password: str = Query(...)):
    users = read_data(USERS_FILE)
    admin = users.get("admin")
    if not admin or not pwd_context.verify(admin_password, admin["password_hash"]):
        raise HTTPException(status_code=403, detail="Unauthorized access")
    return read_data(INVESTMENTS_FILE)

@router.post("/admin/approve_user")
def approve_user(username: str = Form(...), admin_password: str = Form(...)):
    users = read_data(USERS_FILE)
    admin = users.get("admin")
    if not admin or not pwd_context.verify(admin_password, admin["password_hash"]):
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid admin credentials")

    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot modify admin account approval")

    if username not in users:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

    if users[username].get("approved"):
        return {"message": f"User '{username}' is already approved"}

    users[username]["approved"] = True
    write_data(USERS_FILE, users)
    return {"message": f"User '{username}' approved successfully"}
