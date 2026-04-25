from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = "mysecretkey"

# ---------------- DATABASE ----------------
users = []
blacklist = set()

# ---------------- HOME ----------------
@app.route('/')
def home():
    return "SecureShield API is running!"

# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data['username']
    password = data['password']
    role = data.get('role', 'User')

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    users.append({
        "username": username,
        "password": hashed_password,
        "role": role
    })

    return jsonify({"message": "User registered successfully!"})

# ---------------- LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data['username']
    password = data['password']

    for user in users:
        if user['username'] == username:

            if bcrypt.check_password_hash(user['password'], password):

                token = jwt.encode({
                    "username": username,
                    "role": user['role'],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                }, SECRET_KEY, algorithm="HS256")

                return jsonify({"token": token})

            return jsonify({"message": "Wrong password"}), 401

    return jsonify({"message": "User not found"}), 404

# ---------------- TOKEN CHECK ----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        if token in blacklist:
            return jsonify({"message": "Token is blacklisted"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"message": "Invalid or expired token"}), 401

        return f(data, *args, **kwargs)

    return decorated

# ---------------- PROFILE ----------------
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        "message": "Welcome!",
        "user": current_user
    })

# ---------------- ADMIN DELETE ----------------
@app.route('/user/<username>', methods=['DELETE'])
@token_required
def delete_user(current_user, username):

    if current_user['role'] != 'Admin':
        return jsonify({"message": "Access denied! Admins only"}), 403

    for user in users:
        if user['username'] == username:
            users.remove(user)
            return jsonify({"message": "User deleted successfully!"})

    return jsonify({"message": "User not found"}), 404

# ---------------- LOGOUT ----------------
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):

    token = request.headers.get('Authorization')
    blacklist.add(token)

    return jsonify({"message": "Logged out successfully!"})


if __name__ == '__main__':
    app.run(debug=True)