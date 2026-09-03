import os
import re
import json
import secrets
import hmac
import sqlite3

import psycopg
from psycopg.rows import dict_row
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ExifTags
from flask_wtf.csrf import CSRFProtect


# ============================================================
# PATHS / APP
# ============================================================

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
DB = os.path.join(DATA, "postguard.db")
UP = os.path.join(DATA, "uploads")

os.makedirs(UP, exist_ok=True)

app = Flask(__name__)
csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

app.secret_key = os.getenv(

    "POSTGUARD_SECRET",
    secrets.token_hex(32),
)

app.config.update(
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
)

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response

# ============================================================
# DATABASE COMPATIBILITY
# Works with Render PostgreSQL and local SQLite
# ============================================================

class Database:
    def __init__(self):
        database_url = os.getenv("DATABASE_URL")

        if database_url:
            self.postgres = True
            self.connection = psycopg.connect(
                database_url,
                row_factory=dict_row,
            )
        else:
            self.postgres = False
            self.connection = sqlite3.connect(DB)
            self.connection.row_factory = sqlite3.Row

    def _sql(self, sql):
        if self.postgres:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, params=None):
        sql = self._sql(sql)

        if params is None:
            return self.connection.execute(sql)

        return self.connection.execute(sql, params)

    def executemany(self, sql, params):
        sql = self._sql(sql)

        cursor = self.connection.cursor()
        cursor.executemany(sql, params)
        return cursor

    def executescript(self, script):
        if not self.postgres:
            return self.connection.executescript(script)

        # PostgreSQL uses SERIAL for automatically generated IDs.
        script = script.replace(
            "id INTEGER PRIMARY KEY",
            "id SERIAL PRIMARY KEY",
        )

        for statement in script.split(";"):
            statement = statement.strip()

            if statement:
                self.connection.execute(statement)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


def db():
    return Database()


def now():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# DATABASE INITIALISATION
# ============================================================

def init():
    c = db()

    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS principals(
            id INTEGER PRIMARY KEY,
            name TEXT,
            role TEXT,
            risk INTEGER DEFAULT 0,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS checks(
            id INTEGER PRIMARY KEY,
            principal_id INTEGER,
            filename TEXT,
            caption TEXT,
            score INTEGER,
            risk TEXT,
            findings TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY,
            principal_id INTEGER,
            check_id INTEGER,
            risk_score INTEGER,
            caption TEXT,
            severity TEXT,
            category TEXT,
            detail TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'Open',
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY,
            title TEXT,
            status TEXT DEFAULT 'Open',
            owner TEXT,
            notes TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS sources(
            id INTEGER PRIMARY KEY,
            name TEXT,
            kind TEXT,
            status TEXT,
            notes TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            detail TEXT,
            created_at TEXT
        );
        """
    )

    # Add newer columns safely for existing SQLite/PostgreSQL databases.
    def ensure_column(table, column, definition):
        if c.postgres:
            c.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN IF NOT EXISTS {column} {definition}"
            )
            return

        columns = c.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()

        existing = {
            row["name"]
            for row in columns
        }

        if column not in existing:
            c.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {column} {definition}"
            )

    ensure_column("checks", "caption", "TEXT")
    ensure_column("alerts", "check_id", "INTEGER")
    ensure_column("alerts", "risk_score", "INTEGER")
    ensure_column("alerts", "caption", "TEXT")

    # Multi-user ownership. Existing records are assigned to the
    # existing administrator so customer accounts never inherit them.
    ensure_column("principals", "user_id", "INTEGER")
    ensure_column("checks", "user_id", "INTEGER")
    ensure_column("alerts", "user_id", "INTEGER")
    ensure_column("cases", "user_id", "INTEGER")
    ensure_column("users", "enabled", "INTEGER DEFAULT 1")
    c.execute("UPDATE users SET enabled=1 WHERE enabled IS NULL")

    admin_row = c.execute(
        """
        SELECT id
        FROM users
        WHERE role='admin'
        ORDER BY id
        LIMIT 1
        """
    ).fetchone()

    if admin_row:
        admin_id = admin_row["id"]

        c.execute(
            "UPDATE principals SET user_id=? WHERE user_id IS NULL",
            (admin_id,),
        )
        c.execute(
            "UPDATE checks SET user_id=? WHERE user_id IS NULL",
            (admin_id,),
        )
        c.execute(
            "UPDATE alerts SET user_id=? WHERE user_id IS NULL",
            (admin_id,),
        )
        c.execute(
            "UPDATE cases SET user_id=? WHERE user_id IS NULL",
            (admin_id,),
        )

    if not c.execute(
        "SELECT 1 FROM principals LIMIT 1"
    ).fetchone():

        c.executemany(
            """
            INSERT INTO principals(
                name,
                role,
                risk,
                created_at
            )
            VALUES(?,?,?,?)
            """,
            [
                (
                    "Alex Morgan",
                    "Professional Footballer",
                    63,
                    now(),
                ),
                (
                    "Jordan Lee",
                    "Executive",
                    41,
                    now(),
                ),
            ],
        )

    if not c.execute(
        "SELECT 1 FROM sources LIMIT 1"
    ).fetchone():

        c.executemany(
            """
            INSERT INTO sources(
                name,
                kind,
                status,
                notes,
                created_at
            )
            VALUES(?,?,?,?,?)
            """,
            [
                (
                    "Client public profile feed",
                    "Authorised social source",
                    "Demo",
                    "Connector placeholder — no credentials stored.",
                    now(),
                ),
                (
                    "Impersonation watchlist",
                    "Public web source",
                    "Demo",
                    "Connector placeholder for licensed/public data.",
                    now(),
                ),
            ],
        )

    c.commit()
    c.close()


# ============================================================
# AUTHENTICATION / AUTHORISATION
# ============================================================

def auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))

        c = db()
        account = c.execute(
            "SELECT role, enabled FROM users WHERE id=?",
            (session["uid"],),
        ).fetchone()
        c.close()

        if not account:
            session.clear()
            return redirect(url_for("login"))

        if account["enabled"] == 0 and account["role"] != "admin":
            session.clear()
            flash("This PostGuard account has been disabled by an administrator.")
            return redirect(url_for("login"))

        session["role"] = account["role"] or "user"
        return f(*args, **kwargs)

    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            abort(403)

        return f(*args, **kwargs)

    return wrapped


def audit(action, detail=""):
    if "uid" not in session:
        return

    c = db()

    c.execute(
        """
        INSERT INTO audit(
            user_id,
            action,
            detail,
            created_at
        )
        VALUES(?,?,?,?)
        """,
        (
            session["uid"],
            action,
            detail,
            now(),
        ),
    )

    c.commit()
    c.close()


# ============================================================
# RISK RULES
# ============================================================

RULES = [
    (
        r"\b(home|house|my place|front door|back door|garden|bedroom|driveway|garage|back home)\b",
        28,
        "Private location / property",
        "The post may reveal details about a private residence or property.",
        "Remove identifiable property details, house features and location clues.",
        "HIGH",
    ),
    (
        r"\b(i am at|i'm at|currently at|here at|just arrived at|right now at|live from)\b",
        35,
        "Live location disclosure",
        "The post appears to reveal where someone is right now.",
        "Delay the post until after leaving and remove live-location details.",
        "CRITICAL",
    ),
    (
        r"\b(tomorrow|tonight|next week|this weekend|flying|flight|airport|holiday|vacation|abroad|away for|leaving for|heading to)\b",
        24,
        "Travel disclosure",
        "The post may reveal current or future travel plans.",
        "Remove dates, times and destinations or publish only after the trip.",
        "HIGH",
    ),
    (
        r"\b(every morning|every night|every monday|every tuesday|every wednesday|every thursday|every friday|every saturday|every sunday|daily|usual route|usual time|regularly|routine)\b",
        22,
        "Routine / predictable movement",
        "The post may reveal a recurring routine or predictable movement.",
        "Remove repeated timings, routes and regular-location details.",
        "HIGH",
    ),
    (
        r"\b(kids|children|child|daughter|son|school|nursery|college pickup|school run|family)\b",
        20,
        "Family / child exposure",
        "The post may reveal information about family members or children.",
        "Remove names, school details, routines and identifiable family information.",
        "HIGH",
    ),
    (
        r"\b(bodyguard|close protection|security team|security guard|panic room|safe room|alarm code|gate code|entry code|security camera|cctv position)\b",
        40,
        "Security arrangement disclosure",
        "The post may expose protective-security arrangements or access controls.",
        "Do not publish security staffing, access methods, alarm details or camera positions.",
        "CRITICAL",
    ),
    (
        r"\b(car|vehicle|range rover|mercedes|bmw|audi|tesla|number plate|license plate|registration plate|reg plate)\b",
        16,
        "Vehicle exposure",
        "The post may reveal an identifiable vehicle or vehicle-related information.",
        "Blur plates and avoid revealing regular parking locations or travel routines.",
        "MEDIUM",
    ),
    (
        r"\b(address|postcode|post code|street name|house number|flat number|apartment number)\b",
        35,
        "Address / location information",
        "The post appears to contain direct address or location clues.",
        "Remove address, street, postcode and property-number details.",
        "CRITICAL",
    ),
    (
        r"\b(phone number|mobile number|telephone|personal email|email address)\b",
        28,
        "Contact information",
        "The post may expose personal contact information.",
        "Remove personal phone numbers and email addresses before publishing.",
        "HIGH",
    ),
    (
        r"\b(password|passcode|pin|api key|secret key|access token|auth token|recovery code|backup code|one-time code|otp)\b",
        50,
        "Credential / authentication exposure",
        "The post contains language associated with credentials or authentication secrets.",
        "Do not publish passwords, PINs, tokens, recovery codes or one-time codes.",
        "CRITICAL",
    ),
    (
        r"\b(passport|driving licence|driver's license|national insurance|ni number|social security|identity card|id card)\b",
        45,
        "Identity-document exposure",
        "The post may reveal sensitive identity-document information.",
        "Remove or fully redact identity documents and identifying numbers.",
        "CRITICAL",
    ),
    (
        r"\b(bank account|sort code|account number|credit card|debit card|card number|cvv|iban|swift code)\b",
        50,
        "Financial information exposure",
        "The post may expose banking or payment information.",
        "Do not publish banking details, payment-card information or financial identifiers.",
        "CRITICAL",
    ),
    (
        r"\b(ticket|boarding pass|hotel booking|reservation|booking reference|confirmation number)\b",
        25,
        "Travel-document exposure",
        "The post may reveal travel documents or booking information.",
        "Hide booking references, barcodes, QR codes, dates and travel details.",
        "HIGH",
    ),
    (
        r"\b(work badge|staff badge|access badge|key card|keycard|door pass|visitor pass)\b",
        30,
        "Access credential exposure",
        "The post may reveal a physical access credential.",
        "Do not publish readable badges, passes, keycards or access identifiers.",
        "HIGH",
    ),
]



def caption_scan(text):
    score = 5
    findings = []

    for pattern, points, category, detail, recommendation, severity in RULES:
        if re.search(pattern, (text or "").lower()):
            score += points

            findings.append(
                {
                    "category": category,
                    "detail": detail,
                    "recommendation": recommendation,
                    "severity": severity,
                }
            )

    return min(99, score), findings


# ============================================================
# IMAGE SCANNING
# ============================================================

def image_scan(path):
    findings = []
    metadata = {}

    try:
        with Image.open(path) as im:
            metadata = {
                "width": im.width,
                "height": im.height,
                "format": im.format,
            }

            exif = im.getexif()

            if exif:
                metadata["exif_fields"] = len(exif)

                if any(
                    ExifTags.TAGS.get(key) == "GPSInfo"
                    for key in exif
                ):
                    findings.append(
                        {
                            "category": "GPS metadata",
                            "detail": (
                                "GPS metadata is present and may "
                                "reveal the capture location."
                            ),
                            "recommendation": (
                                "Strip GPS metadata before publication."
                            ),
                            "severity": "HIGH",
                        }
                    )

            if im.width * im.height > 30_000_000:
                findings.append(
                    {
                        "category": "High-resolution detail",
                        "detail": (
                            "Very high resolution may expose "
                            "small identifiers."
                        ),
                        "recommendation": (
                            "Review plates, documents, screens, "
                            "addresses and signage at 100% zoom."
                        ),
                        "severity": "LOW",
                    }
                )

            if im.width < 600 or im.height < 600:
                findings.append(
                    {
                        "category": "Low-resolution image",
                        "detail": (
                            "Low resolution limits automated "
                            "visual inspection."
                        ),
                        "recommendation": (
                            "Perform a manual security review."
                        ),
                        "severity": "LOW",
                    }
                )

    except Exception:
        findings.append(
            {
                "category": "Image inspection",
                "detail": "The image could not be inspected.",
                "recommendation": (
                    "Complete a manual review before publishing."
                ),
                "severity": "MEDIUM",
            }
        )

    if not findings:
        findings.append(
            {
                "category": "Image metadata",
                "detail": (
                    "No GPS metadata detected by this scanner."
                ),
                "recommendation": (
                    "Still review visual background and "
                    "platform location tags."
                ),
                "severity": "LOW",
            }
        )

    return findings, metadata


def risk(score):
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MODERATE"

    return "LOW"


# ============================================================
# REGISTRATION
# Public customer registration.
# Existing administrator account remains admin.
# All new registrations are normal users.
# ============================================================

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if "uid" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not email:
            flash("Email address is required.")
            return render_template("register.html")

        email_pattern = (
            r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
            r"@[A-Za-z0-9-]+"
            r"(?:\.[A-Za-z0-9-]+)+$"
        )

        if not re.match(email_pattern, email):
            flash("Enter a valid email address.")
            return render_template("register.html")

        if not password:
            flash("Password is required.")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.")
            return render_template("register.html")

        if len(password) < 12:
            flash("Password must be at least 12 characters.")
            return render_template("register.html")

        c = db()
        existing = c.execute(
            "SELECT id FROM users WHERE email=?",
            (email,),
        ).fetchone()

        if existing:
            c.close()
            flash("An account with that email already exists.")
            return render_template("register.html")

        user = c.execute(
            """
            INSERT INTO users(email, password, role, created_at)
            VALUES(?,?,?,?)
            RETURNING id
            """,
            (
                email,
                generate_password_hash(password),
                "user",
                now(),
            ),
        ).fetchone()

        user_id = user["id"]

        # Give every customer a private principal/profile immediately.
        profile_name = email.split("@", 1)[0].replace(".", " ").replace("_", " ")
        profile_name = profile_name.strip().title() or "My Profile"

        c.execute(
            """
            INSERT INTO principals(
                user_id,
                name,
                role,
                risk,
                created_at
            )
            VALUES(?,?,?,?,?)
            """,
            (
                user_id,
                profile_name,
                "Account holder",
                0,
                now(),
            ),
        )

        c.commit()
        c.close()

        app.logger.info(
            "New PostGuard account registered: user_id=%s",
            user_id,
        )

        flash(
            "Your PostGuard account has been created. "
            "You can now sign in."
        )
        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# SECURE ONE-TIME ADMIN RECOVERY
# Enabled only while the two recovery environment variables exist.
# Delete POSTGUARD_ADMIN_RECOVERY_TOKEN after a successful reset.
# ============================================================

ADMIN_RECOVERY_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PostGuard Admin Recovery</title>
    <style>
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #0b1020;
            color: #f5f7fb;
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
        }
        .card {
            width: min(92vw, 440px);
            background: #151c2f;
            border: 1px solid #2a3550;
            border-radius: 16px;
            padding: 28px;
            box-shadow: 0 20px 60px rgba(0,0,0,.35);
        }
        h1 { margin-top: 0; font-size: 1.55rem; }
        p { color: #b9c3d7; line-height: 1.5; }
        label { display:block; margin-top:16px; margin-bottom:6px; }
        input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            border-radius: 10px;
            border: 1px solid #3a4664;
            background: #0f1526;
            color: #fff;
        }
        button {
            width:100%;
            margin-top:20px;
            padding:12px;
            border:0;
            border-radius:10px;
            font-weight:700;
            cursor:pointer;
        }
        .msg {
            margin-top: 14px;
            padding: 10px 12px;
            border-radius: 10px;
            background: #202a43;
        }
    </style>
</head>
<body>
    <main class="card">
        <h1>PostGuard Admin Recovery</h1>
        <p>This page is active only while the recovery environment variables are configured.</p>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="msg">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <label for="email">Admin email</label>
            <input id="email" name="email" type="email" autocomplete="username" required>

            <label for="token">Recovery token</label>
            <input id="token" name="token" type="password" autocomplete="off" required>

            <label for="password">New password</label>
            <input id="password" name="password" type="password" autocomplete="new-password" minlength="12" required>

            <label for="confirm">Confirm new password</label>
            <input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="12" required>

            <button type="submit">Reset Admin Password</button>
        </form>
    </main>
</body>
</html>
"""


@app.route("/admin/recover", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def admin_recover():
    configured_email = os.getenv(
        "POSTGUARD_ADMIN_EMAIL",
        "",
    ).strip().lower()

    configured_token = os.getenv(
        "POSTGUARD_ADMIN_RECOVERY_TOKEN",
        "",
    )

    # Hide the recovery endpoint completely unless deliberately enabled.
    if not configured_email or not configured_token:
        abort(404)

    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        supplied_token = request.form.get(
            "token",
            "",
        )

        password = request.form.get(
            "password",
            "",
        )

        confirm = request.form.get(
            "confirm",
            "",
        )

        if email != configured_email:
            flash("Recovery details were not accepted.")
            return render_template_string(ADMIN_RECOVERY_PAGE), 400

        if not hmac.compare_digest(
            supplied_token,
            configured_token,
        ):
            flash("Recovery details were not accepted.")
            return render_template_string(ADMIN_RECOVERY_PAGE), 400

        if len(password) < 12:
            flash("New password must be at least 12 characters.")
            return render_template_string(ADMIN_RECOVERY_PAGE), 400

        if password != confirm:
            flash("Passwords do not match.")
            return render_template_string(ADMIN_RECOVERY_PAGE), 400

        c = db()

        user = c.execute(
            "SELECT id FROM users WHERE email=?",
            (email,),
        ).fetchone()

        if user:
            c.execute(
                """
                UPDATE users
                SET password=?, role='admin'
                WHERE id=?
                """,
                (
                    generate_password_hash(password),
                    user["id"],
                ),
            )
            admin_user_id = user["id"]
        else:
            created = c.execute(
                """
                INSERT INTO users(
                    email,
                    password,
                    role,
                    created_at
                )
                VALUES(?,?,?,?)
                RETURNING id
                """,
                (
                    email,
                    generate_password_hash(password),
                    "admin",
                    now(),
                ),
            ).fetchone()
            admin_user_id = created["id"]

        # Preserve ownership of any legacy records that still have no owner.
        c.execute(
            "UPDATE principals SET user_id=? WHERE user_id IS NULL",
            (admin_user_id,),
        )
        c.execute(
            "UPDATE checks SET user_id=? WHERE user_id IS NULL",
            (admin_user_id,),
        )
        c.execute(
            "UPDATE alerts SET user_id=? WHERE user_id IS NULL",
            (admin_user_id,),
        )
        c.execute(
            "UPDATE cases SET user_id=? WHERE user_id IS NULL",
            (admin_user_id,),
        )

        c.commit()
        c.close()

        session.clear()
        flash(
            "Admin password reset successfully. "
            "Sign in, then remove POSTGUARD_ADMIN_RECOVERY_TOKEN from Render."
        )
        return redirect(url_for("login"))

    return render_template_string(ADMIN_RECOVERY_PAGE)


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        c = db()

        user = c.execute(
            "SELECT * FROM users WHERE email=?",
            (email,),
        ).fetchone()

        if user and check_password_hash(
            user["password"],
            password,
        ):
            if user["enabled"] == 0:
                c.close()
                flash("This PostGuard account has been disabled by an administrator.")
                return render_template("login.html"), 403

            configured_admin_email = os.getenv(
                "POSTGUARD_ADMIN_EMAIL",
                "",
            ).strip().lower()

            role = user["role"] or "user"

            # The server-side configured admin email is authoritative.
            # This repairs an account whose database role was accidentally
            # left as "user" while keeping all other accounts unchanged.
            if configured_admin_email and email == configured_admin_email:
                role = "admin"

                if user["role"] != "admin":
                    c.execute(
                        """
                        UPDATE users
                        SET role='admin'
                        WHERE id=?
                        """,
                        (user["id"],),
                    )
                    c.commit()

            c.close()

            session.clear()
            session.permanent = True

            session["uid"] = user["id"]
            session["email"] = email
            session["role"] = role

            return redirect(url_for("home"))

        c.close()

        flash("Invalid credentials.")

    return render_template("login.html")


@app.post("/logout")
@auth
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/")
@auth
def home():
    c = db()

    is_admin = session.get("role") == "admin"
    uid = session["uid"]

    if is_admin:
        principals = c.execute(
            """
            SELECT *
            FROM principals
            ORDER BY risk DESC
            """
        ).fetchall()

        alerts = c.execute(
            """
            SELECT
                a.*,
                p.name AS principal
            FROM alerts a
            LEFT JOIN principals p
                ON p.id = a.principal_id
            ORDER BY a.id DESC
            """
        ).fetchall()

        cases = c.execute(
            """
            SELECT *
            FROM cases
            ORDER BY id DESC
            """
        ).fetchall()

        sources = c.execute(
            "SELECT * FROM sources"
        ).fetchall()

        check_count = c.execute(
            "SELECT COUNT(*) AS n FROM checks"
        ).fetchone()["n"]

    else:
        principals = c.execute(
            """
            SELECT *
            FROM principals
            WHERE user_id=?
            ORDER BY risk DESC
            """,
            (uid,),
        ).fetchall()

        alerts = c.execute(
            """
            SELECT
                a.*,
                p.name AS principal
            FROM alerts a
            LEFT JOIN principals p
                ON p.id = a.principal_id
            WHERE a.user_id=?
            ORDER BY a.id DESC
            """,
            (uid,),
        ).fetchall()

        cases = c.execute(
            """
            SELECT *
            FROM cases
            WHERE user_id=?
            ORDER BY id DESC
            """,
            (uid,),
        ).fetchall()

        sources = []

        check_count = c.execute(
            """
            SELECT COUNT(*) AS n
            FROM checks
            WHERE user_id=?
            """,
            (uid,),
        ).fetchone()["n"]

    stats = {
        "principals": len(principals),
        "alerts": sum(
            alert["status"] == "Open"
            for alert in alerts
        ),
        "checks": check_count,
        "cases": sum(
            case["status"] == "Open"
            for case in cases
        ),
    }

    c.close()

    return render_template(
        "app.html",
        principals=principals,
        alerts=alerts,
        cases=cases,
        sources=sources,
        stats=stats,
        is_admin=is_admin,
    )


# ============================================================
# PRINCIPAL PROFILE / RECORD
# ============================================================

@app.get("/principals/<int:principal_id>")
@auth
def principal_profile(principal_id):
    c = db()

    if session.get("role") == "admin":
        principal = c.execute(
            """
            SELECT *
            FROM principals
            WHERE id=?
            """,
            (principal_id,),
        ).fetchone()
    else:
        principal = c.execute(
            """
            SELECT *
            FROM principals
            WHERE id=? AND user_id=?
            """,
            (
                principal_id,
                session["uid"],
            ),
        ).fetchone()

    if not principal:
        c.close()
        abort(404)

    checks = c.execute(
        """
        SELECT *
        FROM checks
        WHERE principal_id=?
        ORDER BY id DESC
        LIMIT 100
        """,
        (principal_id,),
    ).fetchall()

    alerts = c.execute(
        """
        SELECT *
        FROM alerts
        WHERE principal_id=?
        ORDER BY id DESC
        LIMIT 100
        """,
        (principal_id,),
    ).fetchall()

    c.close()

    return render_template(
        "principal.html",
        principal=principal,
        checks=checks,
        alerts=alerts,
    )


@app.post("/api/principals/<int:principal_id>/publish")
@auth
def publish_principal_post(principal_id):
    """
    Safe publishing gate.

    This endpoint deliberately does not pretend to publish to a social
    network. Real posting requires an authorised OAuth connection and the
    official API for the chosen platform.

    For now it validates the requested post and returns the security result.
    The UI only enables real publishing once a provider integration exists.
    """
    c = db()

    if session.get("role") == "admin":
        principal = c.execute(
            "SELECT * FROM principals WHERE id=?",
            (principal_id,),
        ).fetchone()
    else:
        principal = c.execute(
            """
            SELECT *
            FROM principals
            WHERE id=? AND user_id=?
            """,
            (
                principal_id,
                session["uid"],
            ),
        ).fetchone()

    c.close()

    if not principal:
        return jsonify(error="Principal not found."), 404

    platform = request.form.get(
        "platform",
        "",
    ).strip().lower()

    caption = request.form.get(
        "caption",
        "",
    ).strip()

    allowed_platforms = {
        "instagram",
        "facebook",
        "x",
        "linkedin",
        "tiktok",
    }

    if platform not in allowed_platforms:
        return jsonify(
            error="Choose a supported social platform."
        ), 400

    if not caption and not request.files.get("image"):
        return jsonify(
            error="Add a caption or image before publishing."
        ), 400

    score, findings = caption_scan(caption)

    severities = {
        finding.get("severity")
        for finding in findings
    }

    if "CRITICAL" in severities:
        score = max(score, 80)
    elif "HIGH" in severities:
        score = max(score, 60)

    risk_level = risk(score)

    # Publishing is blocked for HIGH / CRITICAL content.
    if risk_level in ("HIGH", "CRITICAL"):
        return jsonify(
            ok=False,
            blocked=True,
            score=score,
            risk=risk_level,
            findings=findings,
            error=(
                "PostGuard blocked publishing because this post "
                "contains high-risk information."
            ),
        ), 409

    # No social OAuth providers are configured in this MVP yet.
    # Return a clear response rather than pretending the post was published.
    return jsonify(
        ok=False,
        blocked=False,
        connection_required=True,
        score=score,
        risk=risk_level,
        findings=findings,
        platform=platform,
        message=(
            "Security check passed. Connect the authorised "
            f"{platform.title()} account before publishing."
        ),
    ), 501


# ============================================================
# POST / IMAGE SCANNER
# ============================================================

@app.post("/api/scan")
@auth
def scan():
    principal_id = (
        request.form.get("principal_id")
        or None
    )

    c_auth = db()

    try:
        if principal_id:
            if session.get("role") == "admin":
                principal = c_auth.execute(
                    "SELECT id, user_id FROM principals WHERE id=?",
                    (principal_id,),
                ).fetchone()
            else:
                principal = c_auth.execute(
                    """
                    SELECT id, user_id
                    FROM principals
                    WHERE id=? AND user_id=?
                    """,
                    (
                        principal_id,
                        session["uid"],
                    ),
                ).fetchone()

            if not principal:
                return jsonify(error="Principal not found."), 404
        elif session.get("role") != "admin":
            principal = c_auth.execute(
                """
                SELECT id, user_id
                FROM principals
                WHERE user_id=?
                ORDER BY id
                LIMIT 1
                """,
                (session["uid"],),
            ).fetchone()

            if not principal:
                return jsonify(error="No private profile exists for this account."), 400

            principal_id = principal["id"]

    finally:
        c_auth.close()

    caption = request.form.get(
        "caption",
        "",
    )

    score, findings = caption_scan(caption)

    uploaded_file = request.files.get("image")

    filename = None
    path = None
    metadata = {}

    try:
        if uploaded_file and uploaded_file.filename:
            extension = os.path.splitext(
                uploaded_file.filename
            )[1].lower()

            if extension not in [
                ".jpg",
                ".jpeg",
                ".png",
                ".webp",
            ]:
                return jsonify(
                    error="Unsupported image type"
                ), 400

            filename = (
                secrets.token_hex(16)
                + extension
            )

            path = os.path.join(
                UP,
                filename,
            )

            uploaded_file.save(path)

            try:
                with Image.open(path) as img:
                    img.verify()
            except Exception:
                return jsonify(
                    error="Uploaded file is not a valid image."
                ), 400

            image_findings, metadata = image_scan(
                path
            )

            findings += image_findings

            image_points = sum(
                20
                if finding["severity"]
                in ("HIGH", "CRITICAL")
                else 5
                for finding in image_findings
                if finding["category"]
                != "Image metadata"
            )

            score = min(
                99,
                score + image_points,
            )

        # Keep the numeric score aligned with the most serious finding.
        severities = {
            finding.get("severity")
            for finding in findings
        }

        if "CRITICAL" in severities:
            score = max(score, 80)
        elif "HIGH" in severities:
            score = max(score, 60)

        risk_level = risk(score)

        c = db()

        try:
            check_row = c.execute(
                """
                INSERT INTO checks(
                    user_id,
                    principal_id,
                    filename,
                    caption,
                    score,
                    risk,
                    findings,
                    created_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                RETURNING id
                """,
                (
                    session["uid"],
                    principal_id,
                    filename,
                    caption,
                    score,
                    risk_level,
                    json.dumps(findings),
                    now(),
                ),
            ).fetchone()

            check_id = check_row["id"]

            if principal_id:
                c.execute(
                    """
                    UPDATE principals
                    SET risk=?
                    WHERE id=?
                    """,
                    (
                        score,
                        principal_id,
                    ),
                )

            if risk_level in ("HIGH", "CRITICAL"):
                severity_rank = {
                    "CRITICAL": 4,
                    "HIGH": 3,
                    "MEDIUM": 2,
                    "LOW": 1,
                }

                if findings:
                    top_finding = max(
                        findings,
                        key=lambda finding: severity_rank.get(
                            finding.get("severity"),
                            0,
                        ),
                    )
                else:
                    top_finding = {
                        "category": "High-risk post",
                        "detail": "The post exceeded the configured PostGuard risk threshold.",
                        "recommendation": "Review and remove sensitive details before publishing.",
                    }

                c.execute(
                    """
                    INSERT INTO alerts(
                        user_id,
                        principal_id,
                        check_id,
                        risk_score,
                        caption,
                        severity,
                        category,
                        detail,
                        recommendation,
                        created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        session["uid"],
                        principal_id,
                        check_id,
                        score,
                        caption,
                        risk_level,
                        top_finding.get("category", "High-risk post"),
                        top_finding.get(
                            "detail",
                            "The post exceeded the configured PostGuard risk threshold.",
                        ),
                        top_finding.get(
                            "recommendation",
                            "Review and remove sensitive details before publishing.",
                        ),
                        now(),
                    ),
                )

            c.commit()
        finally:
            c.close()

        audit(
            "security_scan",
            f"{risk_level} {score}",
        )

        return jsonify(
            score=score,
            risk=risk_level,
            findings=findings,
            metadata=metadata,
        )

    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                app.logger.exception(
                    "Failed to delete temporary scan image."
                )


# ============================================================
# PRINCIPALS
# ============================================================

@app.post("/api/principals")
@auth
def add_principal():
    data = request.get_json(
        silent=True
    ) or {}

    name = (
        data.get("name")
        or ""
    ).strip()

    role = (
        data.get("role")
        or "Executive"
    ).strip()

    if not name:
        return jsonify(
            error="Name required"
        ), 400

    c = db()

    c.execute(
        """
        INSERT INTO principals(
            user_id,
            name,
            role,
            created_at
        )
        VALUES(?,?,?,?)
        """,
        (
            session["uid"],
            name,
            role,
            now(),
        ),
    )

    c.commit()
    c.close()

    audit(
        "add_principal",
        name,
    )

    return jsonify(ok=True)


# ============================================================
# ALERTS
# ============================================================

@app.post("/api/alerts/<int:alert_id>/close")
@auth
def close_alert(alert_id):
    c = db()

    if session.get("role") == "admin":
        c.execute(
            """
            UPDATE alerts
            SET status='Closed'
            WHERE id=?
            """,
            (alert_id,),
        )
    else:
        c.execute(
            """
            UPDATE alerts
            SET status='Closed'
            WHERE id=? AND user_id=?
            """,
            (
                alert_id,
                session["uid"],
            ),
        )

    c.commit()
    c.close()

    audit(
        "close_alert",
        str(alert_id),
    )

    return jsonify(ok=True)


@app.post("/api/alerts/<int:alert_id>/case")
@auth
def alert_to_case(alert_id):
    c = db()

    alert = c.execute(
        """
        SELECT
            a.*,
            p.name AS principal
        FROM alerts a
        LEFT JOIN principals p
            ON p.id = a.principal_id
        WHERE a.id=?
        """
        + (
            ""
            if session.get("role") == "admin"
            else " AND a.user_id=?"
        ),
        (
            (alert_id,)
            if session.get("role") == "admin"
            else (alert_id, session["uid"])
        ),
    ).fetchone()

    if not alert:
        c.close()
        return jsonify(error="Alert not found."), 404

    if alert["status"] == "Closed":
        c.close()
        return jsonify(error="Closed alerts cannot be converted to cases."), 400

    principal_name = alert["principal"] or "Unassigned"
    severity = alert["severity"] or "Security"
    category = alert["category"] or "Alert"

    title = f"{severity} · {category} · {principal_name}"

    notes = "\n".join([
        f"Created from PostGuard Alert #{alert_id}.",
        f"Principal: {principal_name}",
        f"Risk score: {alert['risk_score'] if alert['risk_score'] is not None else 'Not recorded'}",
        f"Scan ID: {alert['check_id'] if alert['check_id'] is not None else 'Not recorded'}",
        "",
        "Original caption:",
        alert["caption"] or "Not recorded.",
        "",
        "Finding:",
        alert["detail"] or "Not recorded.",
        "",
        "Recommended action:",
        alert["recommendation"] or "Not recorded.",
    ])

    case_row = c.execute(
        """
        INSERT INTO cases(
            user_id,
            title,
            owner,
            notes,
            created_at
        )
        VALUES(?,?,?,?,?)
        RETURNING id
        """,
        (
            session["uid"],
            title,
            session.get("email"),
            notes,
            now(),
        ),
    ).fetchone()

    case_id = case_row["id"]

    c.execute(
        """
        UPDATE alerts
        SET status='In Case'
        WHERE id=?
        """,
        (alert_id,),
    )

    c.commit()
    c.close()

    audit(
        "alert_to_case",
        f"alert={alert_id}, case={case_id}",
    )

    return jsonify(
        ok=True,
        case_id=case_id,
    )


# ============================================================
# CASES
# ============================================================

@app.post("/api/cases")
@auth
def create_case():
    data = request.get_json(
        silent=True
    ) or {}

    title = (
        data.get("title")
        or "Security case"
    ).strip()

    notes = data.get(
        "notes",
        "",
    )

    c = db()

    c.execute(
        """
        INSERT INTO cases(
            user_id,
            title,
            owner,
            notes,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            session["uid"],
            title,
            session.get("email"),
            notes,
            now(),
        ),
    )

    c.commit()
    c.close()

    audit(
        "create_case",
        title,
    )

    return jsonify(ok=True)


@app.post("/api/cases/<int:case_id>/close")
@auth
def close_case(case_id):
    c = db()

    if session.get("role") == "admin":
        c.execute(
            """
            UPDATE cases
            SET status='Closed'
            WHERE id=?
            """,
            (case_id,),
        )
    else:
        c.execute(
            """
            UPDATE cases
            SET status='Closed'
            WHERE id=? AND user_id=?
            """,
            (
                case_id,
                session["uid"],
            ),
        )

    c.commit()
    c.close()

    audit(
        "close_case",
        str(case_id),
    )

    return jsonify(ok=True)


# ============================================================
# MONITORING SOURCES
# ============================================================

@app.post("/api/sources")
@admin_required
def add_source():
    data = request.get_json(
        silent=True
    ) or {}

    name = (
        data.get("name")
        or ""
    ).strip()

    kind = (
        data.get("kind")
        or "Authorised source"
    ).strip()

    if not name:
        return jsonify(
            error="Name required"
        ), 400

    c = db()

    c.execute(
        """
        INSERT INTO sources(
            name,
            kind,
            status,
            notes,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            name,
            kind,
            "Configured",
            (
                "Connector must be implemented "
                "with an official/licensed API."
            ),
            now(),
        ),
    )

    c.commit()
    c.close()

    audit(
        "add_source",
        name,
    )

    return jsonify(ok=True)


# ============================================================
# AUDIT LOG
# ============================================================

@app.get("/api/audit")
@admin_required
def audit_api():
    c = db()

    rows = c.execute(
        """
        SELECT
            a.*,
            u.email
        FROM audit a
        JOIN users u
            ON u.id = a.user_id
        ORDER BY a.id DESC
        LIMIT 150
        """
    ).fetchall()

    c.close()

    return jsonify(
        [dict(row) for row in rows]
    )


# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================

ADMIN_USERS_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PostGuard Admin · Users</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}header,main{padding:24px 28px}header{border-bottom:1px solid #26314a;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}.muted{color:#aeb9ce}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:22px}.card,.table{background:#151c2f;border:1px solid #26314a;border-radius:14px}.card{padding:16px}.num{font-size:1.8rem;font-weight:800;margin-top:6px}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:1100px}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid #26314a}th{color:#aeb9ce;font-size:.8rem;text-transform:uppercase}.btn{display:inline-block;padding:8px 11px;border:1px solid #394762;border-radius:8px;background:#151c2f;color:inherit;text-decoration:none;cursor:pointer}.danger{border-color:#7b3540}.success{border-color:#356747}.pill{display:inline-block;padding:4px 8px;border:1px solid #3b4965;border-radius:999px;font-size:.75rem;text-transform:uppercase}.disabled{opacity:.6}.inline{display:inline;margin:0}
</style></head><body>
<header><div><h1>PostGuard Admin · Registered Users</h1><div class="muted">{{ session.get("email") }} · ADMIN</div></div><div><a class="btn" href="{{ url_for('home') }}">Dashboard</a></div></header>
<main>
<div class="cards"><div class="card"><div class="muted">Registered</div><div class="num">{{ users|length }}</div></div><div class="card"><div class="muted">Customers</div><div class="num">{{ customer_count }}</div></div><div class="card"><div class="muted">Disabled</div><div class="num">{{ disabled_count }}</div></div><div class="card"><div class="muted">Admins</div><div class="num">{{ admin_count }}</div></div></div>
<div class="table"><table><thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Status</th><th>Registered</th><th>Scans</th><th>Alerts</th><th>Cases</th><th>Controls</th></tr></thead><tbody>
{% for user in users %}<tr class="{% if user['enabled']==0 %}disabled{% endif %}"><td>{{ user['id'] }}</td><td>{{ user['email'] }}</td><td><span class="pill">{{ user['role'] or 'user' }}</span></td><td><span class="pill">{{ 'Enabled' if user['enabled'] != 0 else 'Disabled' }}</span></td><td>{{ user['created_at'] or '—' }}</td><td>{{ user['check_count'] }}</td><td>{{ user['alert_count'] }}</td><td>{{ user['case_count'] }}</td><td>{% if user['role'] != 'admin' %}<a class="btn" href="{{ url_for('admin_user_detail',user_id=user['id']) }}">View</a> {% if user['enabled']==0 %}<form class="inline" method="post" action="{{ url_for('admin_enable_user',user_id=user['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn success">Enable</button></form>{% else %}<form class="inline" method="post" action="{{ url_for('admin_disable_user',user_id=user['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn danger" onclick="return confirm('Disable this customer account?')">Disable</button></form>{% endif %}{% else %}<span class="muted">Protected admin</span>{% endif %}</td></tr>{% else %}<tr><td colspan="9">No users found.</td></tr>{% endfor %}
</tbody></table></div><p class="muted">Passwords are never displayed. Disabling a customer blocks login and invalidates their active session on its next request.</p></main></body></html>
"""

ADMIN_USER_DETAIL_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PostGuard Admin · Customer</title><style>:root{color-scheme:dark}body{margin:0;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}header,main{padding:24px 28px}header{border-bottom:1px solid #26314a}.muted{color:#aeb9ce}.btn{display:inline-block;padding:8px 11px;border:1px solid #394762;border-radius:8px;background:#151c2f;color:inherit;text-decoration:none}.table{overflow-x:auto;background:#151c2f;border:1px solid #26314a;border-radius:14px;margin:12px 0 24px}table{width:100%;border-collapse:collapse;min-width:720px}th,td{padding:11px 13px;text-align:left;border-bottom:1px solid #26314a}th{color:#aeb9ce;font-size:.8rem;text-transform:uppercase}</style></head><body>
<header><a class="btn" href="{{ url_for('admin_users') }}">← Registered Users</a><h1>{{ user['email'] }}</h1><div class="muted">{{ user['role'] or 'user' }} · {{ 'Enabled' if user['enabled'] != 0 else 'Disabled' }} · Registered {{ user['created_at'] or '—' }}</div></header><main>
<h2>Recent scans</h2><div class="table"><table><thead><tr><th>ID</th><th>Risk</th><th>Score</th><th>Caption</th><th>Created</th></tr></thead><tbody>{% for r in checks %}<tr><td>{{ r['id'] }}</td><td>{{ r['risk'] }}</td><td>{{ r['score'] }}</td><td>{{ r['caption'] or '—' }}</td><td>{{ r['created_at'] }}</td></tr>{% else %}<tr><td colspan="5">No scans.</td></tr>{% endfor %}</tbody></table></div>
<h2>Alerts</h2><div class="table"><table><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Status</th><th>Created</th></tr></thead><tbody>{% for r in alerts %}<tr><td>{{ r['id'] }}</td><td>{{ r['severity'] }}</td><td>{{ r['category'] }}</td><td>{{ r['status'] }}</td><td>{{ r['created_at'] }}</td></tr>{% else %}<tr><td colspan="5">No alerts.</td></tr>{% endfor %}</tbody></table></div>
<h2>Cases</h2><div class="table"><table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Owner</th><th>Created</th></tr></thead><tbody>{% for r in cases %}<tr><td>{{ r['id'] }}</td><td>{{ r['title'] }}</td><td>{{ r['status'] }}</td><td>{{ r['owner'] or '—' }}</td><td>{{ r['created_at'] }}</td></tr>{% else %}<tr><td colspan="5">No cases.</td></tr>{% endfor %}</tbody></table></div>
</main></body></html>
"""

@app.get("/admin/users")
@admin_required
def admin_users():
    c=db()
    users=c.execute("""
        SELECT u.id,u.email,u.role,u.enabled,u.created_at,
        (SELECT COUNT(*) FROM checks ch WHERE ch.user_id=u.id) AS check_count,
        (SELECT COUNT(*) FROM alerts a WHERE a.user_id=u.id) AS alert_count,
        (SELECT COUNT(*) FROM cases ca WHERE ca.user_id=u.id) AS case_count
        FROM users u ORDER BY CASE WHEN u.role='admin' THEN 0 ELSE 1 END,u.id
    """).fetchall()
    c.close()
    admin_count=sum((u["role"] or "user")=="admin" for u in users)
    customer_count=sum((u["role"] or "user")!="admin" for u in users)
    disabled_count=sum((u["role"] or "user")!="admin" and u["enabled"]==0 for u in users)
    return render_template_string(ADMIN_USERS_PAGE,users=users,admin_count=admin_count,customer_count=customer_count,disabled_count=disabled_count)

@app.post("/admin/users/<int:user_id>/disable")
@admin_required
def admin_disable_user(user_id):
    if user_id==session.get("uid"): abort(400)
    c=db(); user=c.execute("SELECT id,role FROM users WHERE id=?",(user_id,)).fetchone()
    if not user: c.close(); abort(404)
    if user["role"]=="admin": c.close(); abort(403)
    c.execute("UPDATE users SET enabled=0 WHERE id=?",(user_id,)); c.commit(); c.close()
    audit("admin_disable_user",f"user_id={user_id}")
    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/enable")
@admin_required
def admin_enable_user(user_id):
    c=db(); user=c.execute("SELECT id,role FROM users WHERE id=?",(user_id,)).fetchone()
    if not user: c.close(); abort(404)
    if user["role"]=="admin": c.close(); abort(403)
    c.execute("UPDATE users SET enabled=1 WHERE id=?",(user_id,)); c.commit(); c.close()
    audit("admin_enable_user",f"user_id={user_id}")
    return redirect(url_for("admin_users"))

@app.get("/admin/users/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    c=db(); user=c.execute("SELECT id,email,role,enabled,created_at FROM users WHERE id=?",(user_id,)).fetchone()
    if not user: c.close(); abort(404)
    checks=c.execute("SELECT * FROM checks WHERE user_id=? ORDER BY id DESC LIMIT 100",(user_id,)).fetchall()
    alerts=c.execute("SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 100",(user_id,)).fetchall()
    cases=c.execute("SELECT * FROM cases WHERE user_id=? ORDER BY id DESC LIMIT 100",(user_id,)).fetchall()
    c.close()
    return render_template_string(ADMIN_USER_DETAIL_PAGE,user=user,checks=checks,alerts=alerts,cases=cases)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify(
        status="ok",
        service="postguard",
        version="4.6",
    )


# ============================================================
# STARTUP
# ============================================================

init()


if __name__ == "__main__":
    app.run(
        host=os.getenv(
            "HOST",
            "127.0.0.1",
        ),
        port=int(
            os.getenv(
                "PORT",
                "5000",
            )
        ),
    )
