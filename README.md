# CMPE132 Project Implementation

Jairo Manansala

CMPE 132

Spring 2026 SJSUL Project Implementation

This is a Flask and SQLite web application for the CMPE 132 SJSUL project implementation. It implements a RBAC model with user provisioning, authentication, authorization, password hashing and basic library actions. 

## How to Start the Project

### 1. Create and activate a virtual environment (made using powershell)
       python -m venv venv
       .\venv\Scripts\Activate.ps1

### 2. Install required packages
       pip install flask flask-bcrypt

### 3. Create database
       python seed.py

### 4. Run the app
       python app.py

       Then open: http://127.0.0.1:5000


## Main Files Used

- app.py
- database.py
- seed.py
- schema.sql
- sjsul.db
- templates/

## Authentication

Users log in with a username and password. The system checks the users table to find the account and checks if it exists and is active. This is then checked against the stored password hash.

This project uses bcrypt through Flask-Bcrypt to hash password. Plain-text passwords are not stored in the database.

## Authorization

This project uses Role-Based Access Control (RBAC), so each user has a role and each role has specific permissions that the user is allowed to do. 

## Assumptions Made
- The system is for a fictional SJSU Library
- Each user has one role
- Permissions are assigned to roles
- Only admins can create or disable user accounts
- The project uses SQLite for simplicity

## References
- Flask Documentation: https://flask.palletsprojects.com/
- Flask-bcrypt Documentation: https://pypi.org/project/Flask-Bcrypt/
