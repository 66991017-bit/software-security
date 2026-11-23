"""
Secure version for Week 2 scanning practice.
"""
import sqlite3, subprocess, os
from flask import Flask, request
import bcrypt

app = Flask(__name__)

# CWE-798: Fixed hardcoded secrets by loading from environment variables
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: Fixed SQL injection using parameterized query (?)
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: Fixed OS command injection by removing shell=True and passing as a list
    return subprocess.check_output(["ping", "-c", "1", host])

def store_password(pw):
    # CWE-327: Fixed weak hash by using bcrypt
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

if __name__ == "__main__":
    app.run(debug=False)  # CWE-489: Disabled debug mode in production