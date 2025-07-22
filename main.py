from flask import Flask, request, jsonify
import json
import os
from datetime import datetime, timedelta
import bcrypt

app = Flask(__name__)

# Data file path
DATA_FILE = 'data.json'

# Utility functions to load and save data
def load_data():
    if not os.path.exists(DATA_FILE):
        # Initialize file with empty structures
        init_data = {"users": [], "investments": [], "withdrawals": []}
        with open(DATA_FILE, 'w') as f:
            json.dump(init_data, f, indent=4)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Utility functions
def find_user(data, username):
    for user in data['users']:
        if user['username'] == username:
            return user
    return None

def find_user_by_referral(data, ref_code):
    for user in data['users']:
        if user.get('referral_code') == ref_code:
            return user
    return None

def find_investment(data, invest_id):
    for inv in data['investments']:
        if inv['id'] == invest_id:
            return inv
    return None

def is_monday():
    # Monday is 0 for weekday()
    return datetime.now().weekday() == 0

# =========================
# Registration
# =========================
@app.route('/register', methods=['POST'])
def register():
    data = load_data()
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email', '')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    if find_user(data, username):
        return jsonify({'message': 'Username already exists'}), 400
    # Check for referral code in query parameter
    ref_code = request.args.get('ref')
    referred_by = None
    if ref_code:
        ref_user = find_user_by_referral(data, ref_code)
        if ref_user:
            referred_by = ref_user['username']
    # Hash password
    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    # Generate a referral code for new user
    ref_code_new = os.urandom(6).hex()
    # Create new user object
    new_user = {
        'username': username,
        'password': pw_hash,
        'email': email,
        'registered_at': datetime.now().isoformat(),
        'is_approved': False,
        'is_admin': False,
        'balance': 0.0,
        'earnings': 0.0,
        'total_invested': 0.0,
        'last_bonus_time': None,
        'referral_code': ref_code_new,
        'referred_by': referred_by
    }
    data['users'].append(new_user)
    save_data(data)
    return jsonify({'message': 'Registration successful. Await admin approval.'}), 201

# =========================
# Login
# =========================
@app.route('/login', methods=['POST'])
def login():
    data = load_data()
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    user = find_user(data, username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Invalid credentials'}), 401
    return jsonify({'message': 'Login successful', 'is_approved': user['is_approved'], 'is_admin': user['is_admin']}), 200

# =========================
# Create Investment (User Request)
# =========================
@app.route('/invest', methods=['POST'])
def create_investment():
    data = load_data()
    username = request.json.get('username')
    password = request.json.get('password')
    amount = request.json.get('amount')
    if not username or not password or amount is None:
        return jsonify({'message': 'Username, password, and amount required'}), 400
    user = find_user(data, username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Authentication failed'}), 401
    if not user['is_approved']:
        return jsonify({'message': 'Account not approved by admin'}), 403
    try:
        amount = float(amount)
    except:
        return jsonify({'message': 'Invalid amount'}), 400
    if amount <= 0:
        return jsonify({'message': 'Investment amount must be positive'}), 400
    # Create investment request
    invest_id = len(data['investments']) + 1
    investment = {
        'id': invest_id,
        'user': username,
        'amount': amount,
        'is_approved': False
    }
    data['investments'].append(investment)
    save_data(data)
    return jsonify({'message': 'Investment request submitted. Await admin approval.'}), 201

# =========================
# Approve Investment (Admin)
# =========================
@app.route('/admin/approve_investment', methods=['POST'])
def approve_investment():
    data = load_data()
    admin_user = request.json.get('admin_username')
    admin_pass = request.json.get('admin_password')
    invest_id = request.json.get('investment_id')
    if not admin_user or not admin_pass or invest_id is None:
        return jsonify({'message': 'Admin credentials and investment_id required'}), 400
    admin = find_user(data, admin_user)
    if not admin or not bcrypt.checkpw(admin_pass.encode('utf-8'), admin['password'].encode('utf-8')) or not admin.get('is_admin', False):
        return jsonify({'message': 'Admin authentication failed'}), 401
    investment = find_investment(data, invest_id)
    if not investment:
        return jsonify({'message': 'Investment not found'}), 404
    if investment['is_approved']:
        return jsonify({'message': 'Investment already approved'}), 400
    # Approve investment
    investment['is_approved'] = True
    # Credit user balance and total_invested
    user = find_user(data, investment['user'])
    if user:
        user['balance'] += investment['amount']
        user['total_invested'] += investment['amount']
        # Referral bonus
        referrer_name = user.get('referred_by')
        if referrer_name:
            referrer = find_user(data, referrer_name)
            if referrer and referrer.get('is_approved'):
                referrer['balance'] += 50.0
                referrer['earnings'] += 50.0
    save_data(data)
    return jsonify({'message': 'Investment approved and credited'}), 200

# =========================
# Daily Bonus (10% of balance)
# =========================
@app.route('/daily_bonus', methods=['POST'])
def daily_bonus():
    data = load_data()
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    user = find_user(data, username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Authentication failed'}), 401
    if not user['is_approved']:
        return jsonify({'message': 'Account not approved'}), 403
    last_claim = user.get('last_bonus_time')
    now = datetime.now()
    if last_claim:
        # parse stored ISO time
        last_dt = datetime.fromisoformat(last_claim)
        if (now - last_dt) < timedelta(hours=24):
            return jsonify({'message': 'Daily bonus already claimed. Come back later.'}), 400
    # Calculate bonus and credit
    bonus = 0.1 * user['balance']
    user['balance'] += bonus
    user['earnings'] += bonus
    user['last_bonus_time'] = now.isoformat()
    save_data(data)
    return jsonify({'message': f'Daily bonus of {bonus:.2f} credited'}), 200

# =========================
# Profile (to retrieve referral link and details)
# =========================
@app.route('/profile', methods=['POST'])
def profile():
    data = load_data()
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    user = find_user(data, username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Authentication failed'}), 401
    # Construct referral link using host url
    host = request.host_url.rstrip('/')
    referral_link = f"{host}/register?ref={user.get('referral_code')}"
    user_data = {
        'username': user['username'],
        'email': user.get('email'),
        'balance': user['balance'],
        'earnings': user['earnings'],
        'total_invested': user['total_invested'],
        'is_approved': user['is_approved'],
        'referral_link': referral_link
    }
    return jsonify(user_data), 200

# =========================
# Withdraw
# =========================
@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = load_data()
    username = request.json.get('username')
    password = request.json.get('password')
    amount = request.json.get('amount')
    if not username or not password or amount is None:
        return jsonify({'message': 'Username, password, and amount required'}), 400
    user = find_user(data, username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Authentication failed'}), 401
    if not user['is_approved']:
        return jsonify({'message': 'Account not approved'}), 403
    try:
        amount = float(amount)
    except:
        return jsonify({'message': 'Invalid amount'}), 400
    if amount <= 0:
        return jsonify({'message': 'Withdrawal amount must be positive'}), 400
    if amount > user['balance']:
        return jsonify({'message': 'Insufficient balance'}), 400
    # Check minimum 30% of total invested
    min_withdraw = 0.3 * user['total_invested']
    if amount < min_withdraw:
        return jsonify({'message': f'Minimum withdrawal amount is {min_withdraw:.2f}'}), 400
    # Check day is Monday
    if not is_monday():
        return jsonify({'message': 'Withdrawals are only allowed on Mondays'}), 400
    # Process withdrawal
    user['balance'] -= amount
    # Record withdrawal request
    withdraw_id = len(data['withdrawals']) + 1
    data['withdrawals'].append({
        'id': withdraw_id,
        'user': username,
        'amount': amount,
        'date': datetime.now().isoformat()
    })
    save_data(data)
    return jsonify({'message': f'Withdrawal of {amount:.2f} processed'}), 200

# =========================
# Admin - Approve User
# =========================
@app.route('/admin/approve_user', methods=['POST'])
def approve_user():
    data = load_data()
    admin_user = request.json.get('admin_username')
    admin_pass = request.json.get('admin_password')
    username = request.json.get('username')
    if not admin_user or not admin_pass or not username:
        return jsonify({'message': 'Admin credentials and username required'}), 400
    admin = find_user(data, admin_user)
    if not admin or not bcrypt.checkpw(admin_pass.encode('utf-8'), admin['password'].encode('utf-8')) or not admin.get('is_admin', False):
        return jsonify({'message': 'Admin authentication failed'}), 401
    user = find_user(data, username)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user['is_approved']:
        return jsonify({'message': 'User is already approved'}), 400
    user['is_approved'] = True
    save_data(data)
    return jsonify({'message': f'User {username} has been approved'}), 200

# =========================
# Admin - Reset User Password
# =========================
@app.route('/admin/reset_password', methods=['POST'])
def reset_password():
    data = load_data()
    admin_user = request.json.get('admin_username')
    admin_pass = request.json.get('admin_password')
    username = request.json.get('username')
    new_password = request.json.get('new_password')
    if not admin_user or not admin_pass or not username or not new_password:
        return jsonify({'message': 'Admin credentials, username, and new_password required'}), 400
    admin = find_user(data, admin_user)
    if not admin or not bcrypt.checkpw(admin_pass.encode('utf-8'), admin['password'].encode('utf-8')) or not admin.get('is_admin', False):
        return jsonify({'message': 'Admin authentication failed'}), 401
    user = find_user(data, username)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    user['password'] = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    save_data(data)
    return jsonify({'message': f'Password for {username} has been reset'}), 200

if __name__ == '__main__':
    # Ensure data file and default admin user exist
    data = load_data()
    # Create a default admin user if none exists
    if not any(user.get('is_admin') for user in data['users']):
        default_admin_pw = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        admin_user = {
            'username': 'admin',
            'password': default_admin_pw,
            'email': '',
            'registered_at': datetime.now().isoformat(),
            'is_approved': True,
            'is_admin': True,
            'balance': 0.0,
            'earnings': 0.0,
            'total_invested': 0.0,
            'last_bonus_time': None,
            'referral_code': '',
            'referred_by': None
        }
        data['users'].append(admin_user)
        save_data(data)
        print("Default admin created: username='admin', password='admin123'")
    app.run(debug=True)
