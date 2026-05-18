# =========================================
# SIMPLE LOGIN SECURITY SYSTEM
# Beginner Friendly Flask Project
# =========================================

from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# =========================================
# APP SETUP
# =========================================

app = Flask(__name__)

DATABASE = "testusers.db"

MAX_FAILED_ATTEMPTS = 5


# =========================================
# DATABASE CONNECTION
# =========================================

def connect_db():
    return sqlite3.connect(DATABASE)


# =========================================
# CREATE DATABASE TABLES
# =========================================

def init_db():

    conn = connect_db()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        failed_attempts INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0
    )
    """)

    # LOGIN LOGS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ADMIN TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    # DEFAULT ADMIN
    cursor.execute("""
    INSERT OR IGNORE INTO admin (username, password)
    VALUES (?, ?)
    """, (
        "admin",
        generate_password_hash("admin123")
    ))

    conn.commit()
    conn.close()


# =========================================
# SAVE LOGIN LOGS
# =========================================

def save_log(username, ip, status):

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO login_logs (username, ip, status)
    VALUES (?, ?, ?)
    """, (username, ip, status))

    conn.commit()
    conn.close()


# =========================================
# HOME PAGE
# =========================================

@app.route('/')
def home():

    return """
    <h1>🔐 Login Security System</h1>

    <hr>

    <h2>Register</h2>

    <form method="POST" action="/register">

        Username:<br>
        <input name="username"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        <button>Register</button>

    </form>

    <hr>

    <h2>Login</h2>

    <form method="POST" action="/login">

        Username:<br>
        <input name="username"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        <button>Login</button>

    </form>

    <hr>

    <a href="/admin">Admin Panel</a>
    """


# =========================================
# REGISTER USER
# =========================================

@app.route('/register', methods=['POST'])
def register():

    username = request.form['username']
    password = request.form['password']

    hashed_password = generate_password_hash(password)

    conn = connect_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT INTO users (username, password)
        VALUES (?, ?)
        """, (username, hashed_password))

        conn.commit()

    except:
        conn.close()
        return "❌ User already exists"

    conn.close()

    return "✅ Registration Successful"


# =========================================
# LOGIN USER
# =========================================

@app.route('/login', methods=['POST'])
def login():

    username = request.form['username']
    password = request.form['password']

    # USER IP ADDRESS
    ip = request.remote_addr

    conn = connect_db()
    cursor = conn.cursor()

    # FIND USER
    cursor.execute("""
    SELECT password, failed_attempts, is_locked
    FROM users
    WHERE username=?
    """, (username,))

    user = cursor.fetchone()

    # USER NOT FOUND
    if not user:

        save_log(username, ip, "INVALID USER")

        conn.close()

        return "❌ Invalid Username"

    # GET USER DATA
    stored_password = user[0]
    failed_attempts = user[1]
    is_locked = user[2]

    # ACCOUNT LOCKED
    if is_locked == 1:

        save_log(username, ip, "ACCOUNT LOCKED")

        conn.close()

        return "🔒 Account Locked"

    # CORRECT PASSWORD
    if check_password_hash(stored_password, password):

        # RESET FAILED ATTEMPTS
        cursor.execute("""
        UPDATE users
        SET failed_attempts=0
        WHERE username=?
        """, (username,))

        conn.commit()

        save_log(username, ip, "LOGIN SUCCESS")

        conn.close()

        return "✅ Login Successful"

    # WRONG PASSWORD
    failed_attempts += 1

    # LOCK ACCOUNT IF LIMIT REACHED
    lock_account = 0

    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        lock_account = 1

    # UPDATE FAILED ATTEMPTS
    cursor.execute("""
    UPDATE users
    SET failed_attempts=?, is_locked=?
    WHERE username=?
    """, (
        failed_attempts,
        lock_account,
        username
    ))

    conn.commit()

    save_log(username, ip, "WRONG PASSWORD")

    conn.close()

    # ACCOUNT LOCK MESSAGE
    if lock_account == 1:
        return "🔒 Account Locked After Too Many Attempts"

    return f"❌ Wrong Password ({failed_attempts}/5)"


# =========================================
# ADMIN LOGIN
# =========================================

@app.route('/admin', methods=['GET', 'POST'])
def admin():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT password
        FROM admin
        WHERE username=?
        """, (username,))

        admin_data = cursor.fetchone()

        conn.close()

        # CHECK ADMIN PASSWORD
        if admin_data:

            stored_password = admin_data[0]

            if check_password_hash(stored_password, password):

                return """
                <h2>✅ Admin Login Successful</h2>

                <a href="/dashboard">
                Open Dashboard
                </a>
                """

        return "❌ Invalid Admin Login"

    # ADMIN LOGIN PAGE
    return """
    <h2>Admin Login</h2>

    <form method="POST">

        Username:<br>
        <input name="username"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        <button>Login</button>

    </form>
    """


# =========================================
# SECURITY DASHBOARD
# =========================================

@app.route('/dashboard')
def dashboard():

    conn = connect_db()
    cursor = conn.cursor()

    # TOTAL USERS
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # FAILED LOGINS
    cursor.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE status='WRONG PASSWORD'
    """)
    failed_logins = cursor.fetchone()[0]

    # LOCKED ACCOUNTS
    cursor.execute("""
    SELECT COUNT(*)
    FROM users
    WHERE is_locked=1
    """)
    locked_accounts = cursor.fetchone()[0]

    # LAST 10 LOGS
    cursor.execute("""
    SELECT username, ip, status, timestamp
    FROM login_logs
    ORDER BY id DESC
    LIMIT 10
    """)

    logs = cursor.fetchall()

    conn.close()

    # ALERT MESSAGE
    alert = ""

    if failed_logins >= 10:
        alert = """
        <h3 style='color:red'>
        ⚠ High Attack Activity Detected
        </h3>
        """

    # PAGE HTML
    html = f"""
    <h1>🔐 Security Dashboard</h1>

    {alert}

    <hr>

    <h2>System Overview</h2>

    <ul>
        <li>Total Users: {total_users}</li>
        <li>Failed Logins: {failed_logins}</li>
        <li>Locked Accounts: {locked_accounts}</li>
    </ul>

    <hr>

    <h2>Recent Security Logs</h2>
    """

    # SHOW LOGS
    for log in logs:

        username = log[0]
        ip = log[1]
        status = log[2]
        time = log[3]

        html += f"""
        <p>
        User: {username} |
        IP: {ip} |
        Status: {status} |
        Time: {time}
        </p>
        """

    html += """
    <hr>

    <a href='/logs'>View All Logs</a>
    """

    return html


# =========================================
# VIEW ALL LOGS
# =========================================

@app.route('/logs')
def logs():

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT username, ip, status, timestamp
    FROM login_logs
    ORDER BY id DESC
    """)

    logs = cursor.fetchall()

    conn.close()

    html = "<h1>📜 All Security Logs</h1><hr>"

    for log in logs:

        html += f"""
        <p>
        User: {log[0]} |
        IP: {log[1]} |
        Status: {log[2]} |
        Time: {log[3]}
        </p>
        """

    return html


# =========================================
# RUN APPLICATION
# =========================================

if __name__ == '__main__':

    init_db()

    app.run(debug=True)