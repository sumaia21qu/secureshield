# SecureShield - Flask Authentication System

## Description
A secure backend API built using Flask with JWT authentication and role-based access control.

## Features
- User registration with hashed passwords
- Login with JWT authentication
- Admin and User roles
- Protected routes
- Logout with token blacklist

## Tools Used
- Python
- Flask
- Flask-Bcrypt
- PyJWT
- Postman

## How to Run
1. Install dependencies:
   pip install flask flask-bcrypt pyjwt

2. Run the application:
   python app.py

3. Open Postman and test endpoints:
   - /register
   - /login
   - /profile
   - /user/<username>
   - /logout
