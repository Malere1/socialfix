import os
import re
import hmac
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, abort
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

# -----------------------------
# FLASK CONFIGURATION
# -----------------------------

app = Flask(__name__, template_folder="templates")

app.secret_key = os.environ.get(
    "SOCIALFIX_SECRET_KEY",
    "socialfix-development-key-change-before-deployment"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("VERCEL") == "1"
)

# Vercel temporary writable database location.
# IMPORTANT: /tmp is not permanent storage.
DATABASE = os.environ.get(
    "DATABASE_PATH",
    "/tmp/socialfix.db"
)

database_directory = os.path.dirname(DATABASE)
if database_directory:
    os.makedirs(database_directory, exist_ok=True)

BITCOIN_ADDRESS = "bc1qxtu7syt7pev692l9h0eucxac0vuprkdgfl76eg"

SOCIAL_PLATFORMS = [
    "TikTok",
    "Instagram",
    "Facebook",
    "X",
    "YouTube",
    "LinkedIn",
    "WhatsApp"
]

REQUEST_STATUSES = [
    "Pending",
    "In Progress",
    "Resolved",
    "Rejected"
]

# -----------------------------
# DATABASE
# -----------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, timeout=20)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def get_columns(table_name):
    rows = get_db().execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return [row["name"] for row in rows]


def add_column_if_missing(table_name, column_name, definition):
    columns = get_columns(table_name)

    if column_name not in columns:
        get_db().execute(
            f"ALTER TABLE {table_name} "
            f"ADD COLUMN {column_name} {definition}"
        )


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)

    user_columns = get_columns("users")

    if "password_hash" not in user_columns:
        add_column_if_missing(
            "users", "password_hash", "TEXT"
        )

    add_column_if_missing("users", "created_at", "TEXT")

    add_column_if_missing(
        "users", "balance", "REAL NOT NULL DEFAULT 0"
    )

    add_column_if_missing(
        "users", "is_admin", "INTEGER NOT NULL DEFAULT 0"
    )

    add_column_if_missing(
        "users", "is_active", "INTEGER NOT NULL DEFAULT 1"
    )

    user_columns = get_columns("users")

    if "password" in user_columns:
        db.execute("""
            UPDATE users
            SET password_hash = password
            WHERE password_hash IS NULL
               OR password_hash = ''
        """)

    db.execute("""
        UPDATE users
        SET created_at = ?
        WHERE created_at IS NULL OR created_at = ''
    """, (
        datetime.now().isoformat(timespec="seconds"),
    ))

    db.execute("""
        CREATE TABLE IF NOT EXISTS social_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            account_name TEXT NOT NULL,
            account_url TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS support_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            admin_reply TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    add_column_if_missing(
        "support_requests",
        "admin_reply",
        "TEXT"
    )

    db.commit()


# Initialize database when Vercel imports the application.
with app.app_context():
    init_db()


# -----------------------------
# CSRF PROTECTION
# -----------------------------

def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        session_token = session.get("_csrf_token", "")

        if (
            not submitted_token
            or not session_token
            or not hmac.compare_digest(
                submitted_token,
                session_token
            )
        ):
            abort(
                400,
                description=(
                    "Invalid form token. Refresh the page and try again."
                )
            )


# -----------------------------
# AUTHENTICATION
# -----------------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        user = get_db().execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if user is None or not user["is_active"]:
            session.clear()
            flash(
                "Your account is unavailable. Please contact support.",
                "error"
            )
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):

        user = get_db().execute(
            "SELECT is_admin FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if user is None or not user["is_admin"]:
            abort(403)

        return view(*args, **kwargs)

    return wrapped_view


def valid_email(email):
    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        )
    )


def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    return get_db().execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()


# -----------------------------
# HOME
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html")


# -----------------------------
# REGISTRATION
# -----------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password",
            password
        )

        if not name or not email or not password:
            flash("Please fill in all required fields.", "error")
            return render_template("register.html")

        if not valid_email(email):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash(
                "Your password must have at least 8 characters.",
                "error"
            )
            return render_template("register.html")

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return render_template("register.html")

        db = get_db()

        existing_user = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            flash(
                "An account with this email already exists.",
                "error"
            )
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        columns = get_columns("users")

        try:

            if "password" in columns:
                db.execute("""
                    INSERT INTO users (
                        name, email, password,
                        password_hash, created_at,
                        balance, is_admin, is_active
                    )
                    VALUES (?, ?, ?, ?, ?, 0, 0, 1)
                """, (
                    name,
                    email,
                    hashed_password,
                    hashed_password,
                    datetime.now().isoformat(timespec="seconds")
                ))

            else:
                db.execute("""
                    INSERT INTO users (
                        name, email, password_hash,
                        created_at, balance,
                        is_admin, is_active
                    )
                    VALUES (?, ?, ?, ?, 0, 0, 1)
                """, (
                    name,
                    email,
                    hashed_password,
                    datetime.now().isoformat(timespec="seconds")
                ))

            db.commit()

        except sqlite3.IntegrityError:
            db.rollback()
            flash(
                "Unable to create this account. Check the details.",
                "error"
            )
            return render_template("register.html")

        except sqlite3.Error:
            db.rollback()
            app.logger.exception(
                "Database error during registration"
            )
            flash(
                "Registration is temporarily unavailable. Please try again.",
                "error"
            )
            return render_template("register.html")

        flash(
            "Registration successful. You can now log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# -----------------------------
# LOGIN
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user is None or not user["is_active"]:
            flash("Incorrect email or password.", "error")
            return render_template("login.html")

        password_hash = user["password_hash"]

        if not password_hash and "password" in user.keys():
            password_hash = user["password"]

        if not password_hash or not check_password_hash(
            password_hash,
            password
        ):
            flash("Incorrect email or password.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["_csrf_token"] = secrets.token_hex(32)

        flash("Welcome back!", "success")

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# -----------------------------
# DASHBOARD
# -----------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    social_count = get_db().execute(
        """
        SELECT COUNT(*)
        FROM social_accounts
        WHERE user_id = ?
        """,
        (session["user_id"],)
    ).fetchone()[0]

    support_count = get_db().execute(
        """
        SELECT COUNT(*)
        FROM support_requests
        WHERE user_id = ?
        """,
        (session["user_id"],)
    ).fetchone()[0]

    return render_template(
        "dashboard.html",
        user=user,
        social_count=social_count,
        support_count=support_count
    )