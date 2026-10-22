
import os
import re
import hmac
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__, template_folder="templates")

app.secret_key = os.environ.get(
    "SOCIALFIX_SECRET_KEY",
    "socialfix-development-key-change-before-deployment",
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "socialfix.db",
)

BITCOIN_ADDRESS = "bc1qxtu7syt7pev692l9h0eucxac0vuprkdgfl76eg"

SOCIAL_PLATFORMS = [
    "TikTok",
    "Instagram",
    "Facebook",
    "X",
    "YouTube",
    "LinkedIn",
    "WhatsApp",
]

REQUEST_STATUSES = [
    "Pending",
    "In Progress",
    "Resolved",
    "Rejected",
]


# -----------------------------
# DATABASE
# -----------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
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

    # Support older databases that use "password" instead of
    # "password_hash". Keep the existing columns and user records.
    user_columns = get_columns("users")

    if "password_hash" not in user_columns:
        add_column_if_missing(
            "users",
            "password_hash",
            "TEXT",
        )

    add_column_if_missing(
        "users",
        "created_at",
        "TEXT",
    )
    add_column_if_missing(
        "users",
        "balance",
        "REAL NOT NULL DEFAULT 0",
    )
    add_column_if_missing(
        "users",
        "is_admin",
        "INTEGER NOT NULL DEFAULT 0",
    )
    add_column_if_missing(
        "users",
        "is_active",
        "INTEGER NOT NULL DEFAULT 1",
    )

    user_columns = get_columns("users")

    # Copy old password hashes into the new column when necessary.
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
    """, (datetime.now().isoformat(timespec="seconds"),))

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
        "TEXT",
    )

    db.commit()


# -----------------------------
# SECURITY AND FORM PROTECTION
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
                session_token,
            )
        ):
            abort(400, description="Invalid form token. Refresh the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        user = get_db().execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

        if user is None or not user["is_active"]:
            session.clear()
            flash("Your account is unavailable. Please contact support.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        user = get_db().execute(
            "SELECT is_admin FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

        if user is None or not user["is_admin"]:
            abort(403)

        return view(*args, **kwargs)

    return wrapped_view


def valid_email(email):
    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email,
        )
    )


def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    return get_db().execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
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
            password,
        )

        if not name or not email or not password:
            flash("Please fill in all required fields.", "error")
            return render_template("register.html")

        if not valid_email(email):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Your password must have at least 8 characters.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return render_template("register.html")

        db = get_db()

        existing_user = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if existing_user:
            flash("An account with this email already exists.", "error")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)

        try:
            db.execute(
                """
                INSERT INTO users (
                    name,
                    email,
                    password_hash,
                    created_at,
                    balance,
                    is_admin,
                    is_active
                )
                VALUES (?, ?, ?, ?, 0, 0, 1)
                """,
                (
                    name,
                    email,
                    hashed_password,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

            db.commit()

        except sqlite3.IntegrityError:
            db.rollback()
            flash("Unable to create this account. Check the details.", "error")
            return render_template("register.html")

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# -----------------------------
# LOGIN
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user is None or not user["is_active"]:
            flash("Incorrect email or password.", "error")
            return render_template("login.html")

        # This matches the existing database column.
        password_hash = user["password_hash"]

        if not password_hash or not check_password_hash(
            password_hash,
            password,
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
        "SELECT COUNT(*) FROM social_accounts WHERE user_id = ?",
        (session["user_id"],),
    ).fetchone()[0]

    support_count = get_db().execute(
        "SELECT COUNT(*) FROM support_requests WHERE user_id = ?",
        (session["user_id"],),
    ).fetchone()[0]

    return render_template(
        "dashboard.html",
        user=user,
        social_count=social_count,
        support_count=support_count,
    )


# -----------------------------
# SOCIAL ACCOUNT MANAGEMENT
# -----------------------------

@app.route("/social-accounts", methods=["GET", "POST"])
@login_required
def social_accounts():
    db = get_db()

    if request.method == "POST":
        platform = request.form.get("platform", "").strip()
        account_name = request.form.get("account_name", "").strip()
        account_url = request.form.get("account_url", "").strip()

        if platform not in SOCIAL_PLATFORMS:
            flash("Please choose a valid social platform.", "error")
            return redirect(url_for("social_accounts"))

        if not account_name:
            flash("Enter the account name.", "error")
            return redirect(url_for("social_accounts"))

        db.execute(
            """
            INSERT INTO social_accounts (
                user_id,
                platform,
                account_name,
                account_url,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                platform,
                account_name,
                account_url,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        db.commit()

        flash("Social account added successfully.", "success")
        return redirect(url_for("social_accounts"))

    accounts = db.execute(
        """
        SELECT *
        FROM social_accounts
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],),
    ).fetchall()

    return render_template(
        "social_accounts.html",
        accounts=accounts,
        social_accounts=accounts,
        platforms=SOCIAL_PLATFORMS,
    )


@app.route("/social-accounts/delete/<int:account_id>", methods=["POST"])
@login_required
def delete_social_account(account_id):
    db = get_db()

    account = db.execute(
        """
        SELECT id FROM social_accounts
        WHERE id = ? AND user_id = ?
        """,
        (account_id, session["user_id"]),
    ).fetchone()

    if account is None:
        abort(404)

    db.execute(
        "DELETE FROM social_accounts WHERE id = ?",
        (account_id,),
    )
    db.commit()

    flash("Social account removed.", "success")
    return redirect(url_for("social_accounts"))


# -----------------------------
# SUPPORT REQUESTS
# -----------------------------

@app.route("/support", methods=["GET", "POST"])
@login_required
def support():
    db = get_db()

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not message:
            flash("Enter a subject and describe your issue.", "error")
            return redirect(url_for("support"))

        db.execute(
            """
            INSERT INTO support_requests (
                user_id,
                subject,
                message,
                status,
                admin_reply,
                created_at
            )
            VALUES (?, ?, ?, 'Pending', '', ?)
            """,
            (
                session["user_id"],
                subject,
                message,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        db.commit()

        flash("Your support request has been submitted.", "success")
        return redirect(url_for("support"))

    requests_list = db.execute(
        """
        SELECT *
        FROM support_requests
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],),
    ).fetchall()

    return render_template(
        "support.html",
        requests=requests_list,
        support_requests=requests_list,
    )


# -----------------------------
# PAYMENTS
# -----------------------------

@app.route("/payments")
@login_required
def payments():
    return render_template(
        "payments.html",
        bitcoin_address=BITCOIN_ADDRESS,
        balance=current_user()["balance"],
    )


# -----------------------------
# ADMIN DASHBOARD
# -----------------------------

@app.route("/admin")
@admin_required
def admin():
    db = get_db()

    users_count = db.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    accounts_count = db.execute(
        "SELECT COUNT(*) FROM social_accounts"
    ).fetchone()[0]

    requests_count = db.execute(
        "SELECT COUNT(*) FROM support_requests"
    ).fetchone()[0]

    requests_list = db.execute(
        """
        SELECT support_requests.*, users.name, users.email
        FROM support_requests
        JOIN users ON users.id = support_requests.user_id
        ORDER BY support_requests.id DESC
        """
    ).fetchall()

    return render_template(
        "admin.html",
        users_count=users_count,
        accounts_count=accounts_count,
        requests_count=requests_count,
        requests=requests_list,
        support_requests=requests_list,
        statuses=REQUEST_STATUSES,
    )


@app.route(
    "/update-request-status/<int:request_id>",
    methods=["POST"],
)
@app.route(
    "/update_request_status/<int:request_id>",
    methods=["POST"],
)
@admin_required
def update_request_status(request_id):
    status = request.form.get("status", "").strip()
    admin_reply = request.form.get("admin_reply", "").strip()

    if status not in REQUEST_STATUSES:
        flash("Choose a valid request status.", "error")
        return redirect(url_for("admin"))

    db = get_db()

    support_request = db.execute(
        "SELECT id FROM support_requests WHERE id = ?",
        (request_id,),
    ).fetchone()

    if support_request is None:
        abort(404)

    db.execute(
        """
        UPDATE support_requests
        SET status = ?, admin_reply = ?
        WHERE id = ?
        """,
        (status, admin_reply, request_id),
    )
    db.commit()

    flash("Support request updated.", "success")
    return redirect(url_for("admin"))


# -----------------------------
# ADMIN: USERS
# -----------------------------

@app.route("/admin/users")
@admin_required
def manage_users():
    users = get_db().execute(
        """
        SELECT id, name, email, created_at, balance, is_admin, is_active
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()

    return render_template(
        "manage_users.html",
        users=users,
    )


@app.route(
    "/admin/users/<int:user_id>/status",
    methods=["POST"],
)
@admin_required
def update_user_status(user_id):
    if user_id == session["user_id"]:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("manage_users"))

    db = get_db()

    user = db.execute(
        "SELECT id, is_active FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if user is None:
        abort(404)

    new_status = 0 if user["is_active"] else 1

    db.execute(
        "UPDATE users SET is_active = ? WHERE id = ?",
        (new_status, user_id),
    )
    db.commit()

    flash("User status updated.", "success")
    return redirect(url_for("manage_users"))


# -----------------------------
# ADMIN: SOCIAL ACCOUNTS
# -----------------------------

@app.route("/admin/social-accounts")
@admin_required
def admin_social_accounts():
    accounts = get_db().execute(
        """
        SELECT social_accounts.*, users.name, users.email
        FROM social_accounts
        JOIN users ON users.id = social_accounts.user_id
        ORDER BY social_accounts.id DESC
        """
    ).fetchall()

    return render_template(
        "admin_social_accounts.html",
        accounts=accounts,
        social_accounts=accounts,
    )


@app.route(
    "/admin/social-accounts/delete/<int:account_id>",
    methods=["POST"],
)
@admin_required
def admin_delete_social_account(account_id):
    db = get_db()

    account = db.execute(
        "SELECT id FROM social_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()

    if account is None:
        abort(404)

    db.execute(
        "DELETE FROM social_accounts WHERE id = ?",
        (account_id,),
    )
    db.commit()

    flash("Social account deleted.", "success")
    return redirect(url_for("admin_social_accounts"))


# -----------------------------
# LOGOUT
# -----------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


# -----------------------------
# ERROR PAGES
# -----------------------------

@app.errorhandler(400)
def bad_request(error):
    return (
        render_template(
            "error.html",
            code=400,
            message=getattr(
                error,
                "description",
                "Bad request. Refresh the page and try again.",
            ),
        ),
        400,
    )


@app.errorhandler(403)
def forbidden(error):
    return (
        render_template(
            "error.html",
            code=403,
            message="You do not have permission to view this page.",
        ),
        403,
    )


@app.errorhandler(404)
def not_found(error):
    return (
        render_template(
            "error.html",
            code=404,
            message="The page you requested could not be found.",
        ),
        404,
    )


# -----------------------------
# START FLASK
# -----------------------------

if __name__ == "__main__":
    with app.app_context():
        init_db()

    app.run(debug=True)
