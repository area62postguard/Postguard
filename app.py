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
    ensure_column("checks", "safer_caption", "TEXT")
    ensure_column("checks", "safer_check_id", "INTEGER")
    ensure_column("alerts", "check_id", "INTEGER")
    ensure_column("alerts", "risk_score", "INTEGER")
    ensure_column("alerts", "caption", "TEXT")

    # Multi-user ownership. Existing records are assigned to the
    # existing administrator so customer accounts never inherit them.
    ensure_column("principals", "user_id", "INTEGER")
    ensure_column("checks", "user_id", "INTEGER")
    ensure_column("alerts", "user_id", "INTEGER")

    # Case-management columns added for customer incident workflow.
    # Older PostGuard databases only had title/status/owner/notes/created_at,
    # so these migrations are required before customer cases can be created.
    ensure_column("cases", "user_id", "INTEGER")
    ensure_column("cases", "principal_id", "INTEGER")
    ensure_column("cases", "alert_id", "INTEGER")
    ensure_column("cases", "category", "TEXT")
    ensure_column("cases", "severity", "TEXT")

    ensure_column("users", "enabled", "INTEGER DEFAULT 1")
    ensure_column("users", "reset_required", "INTEGER DEFAULT 0")
    c.execute("UPDATE users SET enabled=1 WHERE enabled IS NULL")
    c.execute("UPDATE users SET reset_required=0 WHERE reset_required IS NULL")

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
            "SELECT role, enabled, reset_required FROM users WHERE id=?",
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

        if (
            account["reset_required"] == 1
            and account["role"] != "admin"
            and request.endpoint != "forced_password_reset"
        ):
            return redirect(url_for("forced_password_reset"))

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


AUTH_ENTRY_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Protect what you post</title>
<style>
:root{
    color-scheme:dark;
    --bg:#07101d;
    --panel:#0d1828;
    --panel2:#111f33;
    --line:#243754;
    --text:#f6f8fb;
    --muted:#9aabc2;
    --blue:#87adff;
    --blue2:#5f8ff4;
    --green:#7fe0ae;
    --danger:#ff9797;
}
*{box-sizing:border-box}
html,body{min-height:100%}
body{
    margin:0;
    font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    background:
        radial-gradient(circle at 15% 12%,rgba(74,119,205,.18),transparent 30%),
        radial-gradient(circle at 85% 82%,rgba(47,112,101,.12),transparent 30%),
        var(--bg);
    color:var(--text);
}
.page{min-height:100vh;display:grid;grid-template-columns:minmax(0,1.08fr) minmax(440px,.92fr)}
.hero{
    padding:54px clamp(32px,6vw,92px);
    display:flex;
    flex-direction:column;
    justify-content:space-between;
    border-right:1px solid rgba(135,173,255,.12);
}
.brand{display:flex;align-items:center;gap:12px;font-weight:850;letter-spacing:.02em;font-size:1.15rem}
.brand-mark{
    width:48px;height:48px;object-fit:cover;border-radius:50%;
    border:1px solid #315787;box-shadow:0 10px 30px rgba(0,0,0,.22)
}
.hero-copy{max-width:720px;margin:48px 0}
.hero-logo-wrap{display:flex;justify-content:flex-start;margin-bottom:28px}
.hero-logo{
    width:min(330px,68vw);aspect-ratio:1/1;object-fit:cover;border-radius:50%;
    border:1px solid rgba(135,173,255,.28);
    box-shadow:0 24px 70px rgba(0,0,0,.42),0 0 80px rgba(49,101,191,.10);
}
.eyebrow{
    color:var(--blue);font-size:.78rem;text-transform:uppercase;
    letter-spacing:.16em;font-weight:800;margin-bottom:18px
}
h1{font-size:clamp(2.7rem,5vw,4.9rem);line-height:.98;letter-spacing:-.055em;margin:0 0 24px}
.hero p{color:#bdc8d8;font-size:1.12rem;line-height:1.75;max-width:640px;margin:0}
.points{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:34px}
.point{
    background:rgba(13,24,40,.7);border:1px solid rgba(99,131,181,.24);
    padding:16px;border-radius:14px;backdrop-filter:blur(10px)
}
.point strong{display:block;font-size:.92rem;margin-bottom:5px}
.point span{color:var(--muted);font-size:.8rem;line-height:1.45}
.hero-foot{color:#72849e;font-size:.77rem}

.auth-side{
    display:flex;align-items:center;justify-content:center;
    padding:34px;
    background:rgba(7,13,24,.48);
}
.auth-card{
    width:min(100%,480px);
    background:linear-gradient(180deg,rgba(17,31,51,.96),rgba(11,23,39,.97));
    border:1px solid var(--line);
    border-radius:22px;
    padding:28px;
    box-shadow:0 28px 80px rgba(0,0,0,.32);
}
.auth-head h2{font-size:1.65rem;margin:0 0 7px;letter-spacing:-.025em}
.auth-head p{margin:0;color:var(--muted);font-size:.92rem;line-height:1.55}
.switch{
    display:grid;grid-template-columns:1fr 1fr;
    background:#091524;border:1px solid #213450;
    padding:4px;border-radius:12px;margin:22px 0
}
.switch a{
    text-decoration:none;color:#91a2ba;text-align:center;
    padding:10px;border-radius:9px;font-size:.88rem;font-weight:750
}
.switch a.active{background:#172943;color:white;box-shadow:0 3px 12px rgba(0,0,0,.2)}
.flash{
    border:1px solid #5b3c48;background:#281923;color:#ffd4da;
    border-radius:11px;padding:11px 13px;margin:0 0 16px;font-size:.86rem
}
.field{margin-top:15px}
label{display:block;font-size:.82rem;font-weight:750;margin:0 0 7px;color:#dbe4f2}
.input-wrap{position:relative}
input{
    width:100%;padding:13px 14px;border-radius:11px;
    border:1px solid #314662;background:#091524;color:white;
    outline:none;font:inherit
}
input:focus{border-color:#668ed0;box-shadow:0 0 0 3px rgba(102,142,208,.13)}
input::placeholder{color:#61748f}
.toggle{
    position:absolute;right:10px;top:50%;transform:translateY(-50%);
    background:none;border:0;color:#8da1bd;cursor:pointer;font-size:.76rem;font-weight:700
}
.primary{
    width:100%;border:0;margin-top:20px;padding:13px 16px;border-radius:11px;
    background:linear-gradient(135deg,#ecf3ff,#bcd1fa);
    color:#07101d;font-weight:850;font-size:.92rem;cursor:pointer
}
.primary:hover{filter:brightness(1.03)}
.note{color:#7589a4;font-size:.75rem;line-height:1.55;margin-top:14px}
.security{
    margin-top:22px;padding-top:18px;border-top:1px solid #20314b;
    display:flex;gap:10px;align-items:flex-start;color:#8ea1bc;font-size:.78rem;line-height:1.5
}
.security svg{flex:0 0 auto;margin-top:1px}
.mini-link{color:#aac6ff;text-decoration:none}
@media(max-width:980px){
    .page{grid-template-columns:1fr}
    .hero{padding:32px 24px;border-right:0;border-bottom:1px solid rgba(135,173,255,.12)}
    .hero-copy{margin:38px 0 30px}
    .hero-logo{width:min(260px,72vw)}
    h1{font-size:clamp(2.6rem,11vw,4.6rem)}
    .points{grid-template-columns:1fr}
    .auth-side{padding:28px 18px 48px}
}
</style>
</head>
<body>
<div class="page">
    <section class="hero">
        <div class="brand">
            <img class="brand-mark" src="{{ url_for('static', filename='postguard_logo.jpg') }}" alt="PostGuard logo">
            <span>POSTGUARD</span>
        </div>

        <div class="hero-copy">
            <div class="hero-logo-wrap">
                <img class="hero-logo" src="{{ url_for('static', filename='postguard_logo.jpg') }}" alt="PostGuard — Protect What You Post">
            </div>
            <div class="eyebrow">Personal digital risk protection</div>
            <h1>Protect what<br>you post.</h1>
            <p>
                Check social-media posts for privacy and security risks before they go live.
                PostGuard identifies sensitive details, explains the risk and helps you create
                a safer version before publishing.
            </p>

            <div class="points">
                <div class="point">
                    <strong>Pre-post risk checks</strong>
                    <span>Review captions and images before they become public.</span>
                </div>
                <div class="point">
                    <strong>Clear security decisions</strong>
                    <span>Get simple SAFE TO POST or DO NOT POST guidance.</span>
                </div>
                <div class="point">
                    <strong>Private by design</strong>
                    <span>Your account, scans, alerts and cases remain separated from other users.</span>
                </div>
            </div>
        </div>

        <div class="hero-foot">PostGuard Security · Secure access portal</div>
    </section>

    <section class="auth-side">
        <main class="auth-card">
            <div class="auth-head">
                {% if mode == 'register' %}
                    <h2>Create your PostGuard account</h2>
                    <p>Set up secure access to your private PostGuard workspace.</p>
                {% else %}
                    <h2>Welcome back</h2>
                    <p>Sign in to your PostGuard intelligence centre.</p>
                {% endif %}
            </div>

            <nav class="switch" aria-label="Account access">
                <a href="{{ url_for('login') }}" class="{% if mode == 'login' %}active{% endif %}">Returning user</a>
                <a href="{{ url_for('register') }}" class="{% if mode == 'register' %}active{% endif %}">New user</a>
            </nav>

            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    {% for message in messages %}
                        <div class="flash">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            {% if mode == 'register' %}
            <form method="post" action="{{ url_for('register') }}" autocomplete="on">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

                <div class="field">
                    <label for="email">Email address</label>
                    <input id="email" name="email" type="email" autocomplete="email"
                           placeholder="you@example.com" required>
                </div>

                <div class="field">
                    <label for="password">Create password</label>
                    <div class="input-wrap">
                        <input id="password" name="password" type="password"
                               autocomplete="new-password" minlength="12"
                               placeholder="Minimum 12 characters" required>
                        <button class="toggle" type="button" data-target="password">SHOW</button>
                    </div>
                </div>

                <div class="field">
                    <label for="confirm">Confirm password</label>
                    <div class="input-wrap">
                        <input id="confirm" name="confirm" type="password"
                               autocomplete="new-password" minlength="12"
                               placeholder="Repeat your password" required>
                        <button class="toggle" type="button" data-target="confirm">SHOW</button>
                    </div>
                </div>

                <button class="primary" type="submit">Create secure account</button>
                <div class="note">
                    By creating an account, you are creating a private PostGuard workspace.
                    Passwords are stored as secure hashes rather than readable passwords.
                </div>
            </form>
            {% else %}
            <form method="post" action="{{ url_for('login') }}" autocomplete="on">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

                <div class="field">
                    <label for="email">Email address</label>
                    <input id="email" name="email" type="email" autocomplete="username"
                           placeholder="you@example.com" required autofocus>
                </div>

                <div class="field">
                    <label for="password">Password</label>
                    <div class="input-wrap">
                        <input id="password" name="password" type="password"
                               autocomplete="current-password" placeholder="Your password" required>
                        <button class="toggle" type="button" data-target="password">SHOW</button>
                    </div>
                </div>

                <button class="primary" type="submit">Sign in securely</button>
                <div class="note">
                    New to PostGuard?
                    <a class="mini-link" href="{{ url_for('register') }}">Create an account</a>.
                    Administrators use this same secure sign-in.
                </div>
            </form>
            {% endif %}

            <div class="security">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <rect x="5" y="10" width="14" height="10" rx="2" stroke="#8ea1bc" stroke-width="1.7"/>
                    <path d="M8 10V7a4 4 0 0 1 8 0v3" stroke="#8ea1bc" stroke-width="1.7"/>
                </svg>
                <div>
                    Secure session protection, rate-limited authentication and CSRF protection are enabled.
                </div>
            </div>
        </main>
    </section>
</div>

<script>
document.querySelectorAll(".toggle").forEach(function(button){
    button.addEventListener("click", function(){
        var input = document.getElementById(button.dataset.target);
        var showing = input.type === "text";
        input.type = showing ? "password" : "text";
        button.textContent = showing ? "SHOW" : "HIDE";
    });
});
</script>
</body>
</html>
"""


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
            return render_template_string(AUTH_ENTRY_PAGE, mode="register")

        email_pattern = (
            r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
            r"@[A-Za-z0-9-]+"
            r"(?:\.[A-Za-z0-9-]+)+$"
        )

        if not re.match(email_pattern, email):
            flash("Enter a valid email address.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register")

        if not password:
            flash("Password is required.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register")

        if password != confirm:
            flash("Passwords do not match.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register")

        if len(password) < 12:
            flash("Password must be at least 12 characters.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register")

        c = db()
        existing = c.execute(
            "SELECT id FROM users WHERE email=?",
            (email,),
        ).fetchone()

        if existing:
            c.close()
            flash("An account with that email already exists.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register")

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

    return render_template_string(AUTH_ENTRY_PAGE, mode="register")


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
                return render_template_string(AUTH_ENTRY_PAGE, mode="login"), 403

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

            if user["reset_required"] == 1 and role != "admin":
                return redirect(url_for("forced_password_reset"))

            return redirect(url_for("home"))

        c.close()

        flash("Invalid credentials.")

    return render_template_string(AUTH_ENTRY_PAGE, mode="login")


@app.post("/logout")
@auth
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================


CUSTOMER_DASHBOARD_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Dashboard</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09101d;color:#f5f7fb}
a{color:inherit}
.shell{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.sidebar{background:#0d1525;border-right:1px solid #22304a;padding:24px 18px}
.brand{font-size:1.25rem;font-weight:800;letter-spacing:.03em;margin-bottom:28px}
.brand span{color:#8cb4ff}
.nav{display:grid;gap:8px}
.nav a{padding:11px 12px;border-radius:10px;text-decoration:none;color:#c9d3e5}
.nav a:hover,.nav .active{background:#17233a;color:#fff}
.main{padding:28px}
.topbar{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap;margin-bottom:26px}
.eyebrow{color:#8ea0ba;font-size:.85rem;text-transform:uppercase;letter-spacing:.08em}
h1{margin:.2rem 0 0;font-size:2rem}
.actions{display:flex;gap:10px;flex-wrap:wrap}
.btn{display:inline-block;padding:11px 15px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;text-decoration:none;cursor:pointer}
.btn.primary{background:#f5f7fb;color:#0b1020;border-color:#f5f7fb;font-weight:750}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:22px}
.card{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:18px}
.metric{font-size:1.8rem;font-weight:800;margin-top:7px}
.muted{color:#95a4ba}
.risk{font-weight:800}
.section-grid{display:grid;grid-template-columns:1.25fr .75fr;gap:18px;margin-bottom:18px}
.panel{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:18px;min-width:0}
.panel h2{margin:0 0 14px;font-size:1.05rem}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:11px 9px;border-bottom:1px solid #22304a;font-size:.92rem;vertical-align:top}
th{color:#8ea0ba;font-size:.76rem;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:4px 8px;border:1px solid #40506c;border-radius:999px;font-size:.74rem;font-weight:700}
.empty{padding:22px 0;color:#95a4ba}
.quick{display:grid;gap:10px}
.quick a{display:block;text-decoration:none;border:1px solid #2b3b59;border-radius:12px;padding:14px;background:#0d1525}
.quick strong{display:block;margin-bottom:4px}
.alert-item{padding:12px 0;border-bottom:1px solid #22304a}
.alert-item:last-child{border-bottom:0}
@media(max-width:980px){.shell{grid-template-columns:1fr}.sidebar{display:none}.cards{grid-template-columns:repeat(2,1fr)}.section-grid{grid-template-columns:1fr}}
@media(max-width:600px){.main{padding:18px}.cards{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="shell">
<aside class="sidebar">
    <div class="brand">POST<span>GUARD</span></div>
    <nav class="nav">
        <a class="active" href="{{ url_for('home') }}">Dashboard</a>
        <a href="{{ url_for('check_post') }}">Check a Post</a>
        <a href="{{ url_for('home') }}#active-alerts">Alerts</a>
        <a href="{{ url_for('home') }}#recent-cases">Cases</a>
        <a href="{{ url_for('customer_cases_list') }}">My Cases</a>
        <a href="{{ url_for('account') }}">My Account</a>
        <form method="post" action="{{ url_for('logout') }}" style="margin:8px 0 0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit" style="width:100%;padding:11px 12px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;cursor:pointer;text-align:left">Log out</button>
        </form>
    </nav>
</aside>

<main class="main">
    <div class="topbar">
        <div>
            <div class="eyebrow">Personal security dashboard</div>
            <h1>Protect what you post.</h1>
            <div class="muted">Review your recent exposure, alerts and post checks.</div>
        </div>
        <div class="actions">
            <a class="btn" href="{{ url_for('account') }}">My Account</a>
            <a class="btn primary" href="{{ url_for('check_post') }}">Check a Post</a>
            <form method="post" action="{{ url_for('logout') }}" style="margin:0">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn" type="submit">Log out</button>
            </form>
        </div>
    </div>

    <section class="cards">
        <div class="card">
            <div class="muted">Current risk</div>
            <div class="metric risk">{{ current_risk }}</div>
            <div class="muted">Latest score: {{ current_score }}/100</div>
        </div>
        <div class="card">
            <div class="muted">Posts checked</div>
            <div class="metric">{{ scan_count }}</div>
        </div>
        <div class="card">
            <div class="muted">Active alerts</div>
            <div class="metric">{{ alert_count }}</div>
        </div>
        <div class="card">
            <div class="muted">Cases</div>
            <div class="metric">{{ case_count }}</div>
        </div>
    </section>

    <section class="section-grid" id="check-post">
        <div class="panel">
            <h2>Recent post checks</h2>
            {% if recent_checks %}
            <table>
                <thead><tr><th>Risk</th><th>Score</th><th>Caption</th><th>Created</th></tr></thead>
                <tbody>
                {% for row in recent_checks %}
                <tr>
                    <td><span class="pill">{{ row["risk"] }}</span></td>
                    <td>{{ row["score"] }}/100</td>
                    <td>{{ row["caption"] or "Image / metadata check" }}</td>
                    <td>{{ row["created_at"] }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty">No posts checked yet. Use <strong>Check a Post</strong> to run your first assessment.</div>
            {% endif %}
        </div>

        <div class="panel">
            <h2>Quick actions</h2>
            <div class="quick">
                <a href="{{ url_for('check_post') }}">
                    <strong>Check a Post</strong>
                    <span class="muted">Scan a caption or image before publishing.</span>
                </a>
                <a href="{{ url_for('home') }}#active-alerts">
                    <strong>Review Alerts</strong>
                    <span class="muted">See exposure that needs attention.</span>
                </a>
                <a href="{{ url_for('account') }}">
                    <strong>Account Security</strong>
                    <span class="muted">Change your password or manage your account.</span>
                </a>
            </div>
        </div>
    </section>

    <section class="section-grid">
        <div class="panel" id="active-alerts">
            <h2>Active alerts</h2>
            {% if active_alerts %}
                {% for row in active_alerts %}
                <a class="alert-item" href="{{ url_for('customer_alert_detail', alert_id=row['id']) }}" style="display:block;text-decoration:none;color:inherit">
                    <strong>{{ row["severity"] }} · {{ row["category"] }}</strong>
                    <div class="muted">{{ row["status"] }} · {{ row["created_at"] }}</div>
                </a>
                {% endfor %}
            {% else %}
                <div class="empty">No active alerts.</div>
            {% endif %}
        </div>

        <div class="panel">
            <h2>Your PostGuard profile</h2>
            {% if principals %}
                {% for row in principals[:3] %}
                <div class="alert-item">
                    <strong>{{ row["name"] }}</strong>
                    <div class="muted">{{ row["role"] or "Protected account" }} · Risk {{ row["risk"] }}</div>
                </div>
                {% endfor %}
            {% else %}
                <div class="empty">No profile records found.</div>
            {% endif %}
        </div>
    </section>
</main>
</div>
</body>
</html>
"""


@app.get("/")
@auth
def home():
    c = db()

    is_admin = session.get("role") == "admin"

    if is_admin:
        principals = c.execute(
            """
            SELECT *
            FROM principals
            ORDER BY id DESC
            """
        ).fetchall()

        alerts = c.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

        cases = c.execute(
            """
            SELECT *
            FROM cases
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

        checks = c.execute(
            """
            SELECT *
            FROM checks
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

        c.close()

        stats = {
            "principals": len(principals),
            "alerts": len(alerts),
            "cases": len(cases),
            "checks": len(checks),
        }

        return render_template(
            "app.html",
            principals=principals,
            alerts=alerts,
            cases=cases,
            checks=checks,
            stats=stats,
        )

    uid = session["uid"]

    principals = c.execute(
        """
        SELECT *
        FROM principals
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (uid,),
    ).fetchall()

    recent_checks = c.execute(
        """
        SELECT *
        FROM checks
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 8
        """,
        (uid,),
    ).fetchall()

    active_alerts = c.execute(
        """
        SELECT *
        FROM alerts
        WHERE user_id=?
          AND COALESCE(status, '') NOT IN ('Closed', 'Resolved')
        ORDER BY id DESC
        LIMIT 8
        """,
        (uid,),
    ).fetchall()

    recent_cases = c.execute(
        """
        SELECT *
        FROM cases
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 6
        """,
        (uid,),
    ).fetchall()

    scan_count = c.execute(
        "SELECT COUNT(*) AS n FROM checks WHERE user_id=?",
        (uid,),
    ).fetchone()["n"]

    alert_count = c.execute(
        """
        SELECT COUNT(*) AS n
        FROM alerts
        WHERE user_id=?
          AND COALESCE(status, '') NOT IN ('Closed', 'Resolved')
        """,
        (uid,),
    ).fetchone()["n"]

    case_count = c.execute(
        "SELECT COUNT(*) AS n FROM cases WHERE user_id=?",
        (uid,),
    ).fetchone()["n"]

    latest = recent_checks[0] if recent_checks else None
    current_risk = latest["risk"] if latest else "LOW"
    current_score = latest["score"] if latest else 0

    c.close()

    return render_template_string(
        CUSTOMER_DASHBOARD_PAGE,
        principals=principals,
        recent_checks=recent_checks,
        active_alerts=active_alerts,
        recent_cases=recent_cases,
        scan_count=scan_count,
        alert_count=alert_count,
        case_count=case_count,
        current_risk=current_risk,
        current_score=current_score,
    )

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



CUSTOMER_CHECK_POST_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Check a Post</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09101d;color:#f5f7fb}
a{color:inherit}
.shell{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.sidebar{background:#0d1525;border-right:1px solid #22304a;padding:24px 18px}
.brand{font-size:1.25rem;font-weight:800;letter-spacing:.03em;margin-bottom:28px}
.brand span{color:#8cb4ff}
.nav{display:grid;gap:8px}
.nav a{padding:11px 12px;border-radius:10px;text-decoration:none;color:#c9d3e5}
.nav a:hover,.nav .active{background:#17233a;color:#fff}
.main{padding:28px;max-width:1200px;width:100%}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.eyebrow{color:#8ea0ba;font-size:.85rem;text-transform:uppercase;letter-spacing:.08em}
h1{margin:.2rem 0 0;font-size:2rem}
.muted{color:#95a4ba}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.card{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:20px}
label{display:block;font-weight:700;margin:14px 0 7px}
.field{width:100%;padding:12px;border-radius:10px;border:1px solid #31415e;background:#0d1525;color:#fff}
textarea.field{min-height:180px;resize:vertical}
.btn{display:inline-block;padding:11px 15px;border-radius:10px;border:1px solid #31415e;background:#f5f7fb;color:#0b1020;text-decoration:none;cursor:pointer;font-weight:750}
.btn.secondary{background:#151f33;color:#fff}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.result-head{display:flex;align-items:center;gap:16px;margin-bottom:16px}
.score{width:82px;height:82px;border-radius:50%;display:grid;place-items:center;border:3px solid #40506c;font-size:1.5rem;font-weight:800}
.finding{border:1px solid #2c3a55;border-radius:12px;padding:14px;margin-top:10px;background:#0d1525}
.finding strong{display:block;margin-bottom:6px}
.status{font-size:1.5rem;font-weight:800}
.safe{color:#7dd3a7}.warn{color:#f6c56f}.danger{color:#ff8c8c}
.preview{max-width:100%;max-height:260px;border-radius:12px;margin-top:10px;display:none}
@media(max-width:850px){.shell{grid-template-columns:1fr}.sidebar{display:none}.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="shell">
<aside class="sidebar">
    <div class="brand">POST<span>GUARD</span></div>
    <nav class="nav">
        <a href="{{ url_for('home') }}">Dashboard</a>
        <a class="active" href="{{ url_for('check_post') }}">Check a Post</a>
        <a href="{{ url_for('account') }}">My Account</a>
        <form method="post" action="{{ url_for('logout') }}" style="margin:8px 0 0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit" style="width:100%;padding:11px 12px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;cursor:pointer;text-align:left">Log out</button>
        </form>
    </nav>
</aside>

<main class="main">
    <div class="top">
        <div>
            <div class="eyebrow">Pre-publication security check</div>
            <h1>Check a Post</h1>
            <div class="muted">Scan your proposed caption and image before publishing.</div>
        </div>
        <div class="actions">
            <a class="btn secondary" href="{{ url_for('home') }}">Back to Dashboard</a>
            <form method="post" action="{{ url_for('logout') }}" style="margin:0">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn secondary" type="submit">Log out</button>
            </form>
        </div>
    </div>

    <div class="grid">
        <section class="card">
            <form id="scanForm">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="hidden" id="original_check_id" name="original_check_id" value="">
                <input type="hidden" id="safer_caption_field" name="safer_caption" value="">

                <label for="principal_id">Profile</label>
                <select id="principal_id" name="principal_id" class="field">
                    {% for p in principals %}
                    <option value="{{ p['id'] }}">{{ p['name'] }}</option>
                    {% endfor %}
                </select>

                <label for="image">Image</label>
                <input id="image" name="image" type="file" accept="image/*" class="field">
                <img id="preview" class="preview" alt="Selected image preview">

                <label for="caption">Caption</label>
                <textarea id="caption" name="caption" class="field" placeholder="Paste the caption you plan to post..."></textarea>

                <div class="actions">
                    <button id="scanButton" class="btn" type="submit">Run PostGuard Check</button>
                </div>
            </form>
        </section>

        <section class="card">
            <div class="result-head">
                <div class="score" id="score">--</div>
                <div>
                    <div class="status" id="risk">Awaiting scan</div>
                    <div class="muted" id="summary">PostGuard will explain any privacy or security exposure detected.</div>
                </div>
            </div>
            <div id="decision" class="finding" style="margin-bottom:14px;border-width:2px">
                <strong id="decisionTitle">AWAITING DECISION</strong>
                <div class="muted" id="decisionText" style="margin-top:6px">Run the PostGuard check to get a clear publishing decision.</div>
            </div>
            <div id="findings"></div>
            <div id="saferBox" class="finding" style="display:none;margin-top:16px">
                <strong>Safer caption suggestion</strong>
                <div id="saferCaption" style="margin-top:8px"></div>
                <div class="actions">
                    <button type="button" class="btn" id="generateSafer">Create Safer Post</button>
                    <button type="button" class="btn secondary" id="rescanSafer">Use & Re-scan Safer Post</button>
                    <button type="button" class="btn secondary" id="copySafer">Copy safer caption</button>
                </div>
            </div>
        </section>
    </div>
</main>
</div>

<script>
const form = document.getElementById("scanForm");
const imageInput = document.getElementById("image");
const preview = document.getElementById("preview");
const scoreEl = document.getElementById("score");
const riskEl = document.getElementById("risk");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const decisionEl = document.getElementById("decision");
const decisionTitle = document.getElementById("decisionTitle");
const decisionText = document.getElementById("decisionText");
const saferBox = document.getElementById("saferBox");
const saferCaptionEl = document.getElementById("saferCaption");
const generateSafer = document.getElementById("generateSafer");
const rescanSafer = document.getElementById("rescanSafer");
const copySafer = document.getElementById("copySafer");
const button = document.getElementById("scanButton");
const originalCheckField = document.getElementById("original_check_id");
const saferCaptionField = document.getElementById("safer_caption_field");
let lastCheckId = null;
let originalRiskyCheckId = null;

imageInput.addEventListener("change", () => {
    const file = imageInput.files && imageInput.files[0];
    if (!file) {
        preview.style.display = "none";
        preview.removeAttribute("src");
        return;
    }
    preview.src = URL.createObjectURL(file);
    preview.style.display = "block";
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    button.textContent = "Scanning...";
    findingsEl.innerHTML = "";
    saferBox.style.display = "none";
    summaryEl.textContent = "Analysing your post...";
    decisionTitle.textContent = "CHECKING POST...";
    decisionText.textContent = "PostGuard is analysing the proposed post.";
    decisionEl.style.borderColor = "#40506c";
    decisionEl.style.background = "#0d1525";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            body: new FormData(form),
            credentials: "same-origin"
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "The scan could not be completed.");
        }

        if (data.check_id) {
            lastCheckId = data.check_id;
        }
        originalCheckField.value = "";
        saferCaptionField.value = "";

        scoreEl.textContent = (data.score ?? 0) + "/100";
        riskEl.textContent = data.risk || "UNKNOWN";

        const risk = (data.risk || "").toUpperCase();

        if (
            data.check_id &&
            (risk === "HIGH" || risk === "CRITICAL" || risk === "MODERATE") &&
            !originalCheckField.value
        ) {
            originalRiskyCheckId = data.check_id;
        }

        riskEl.className = "status " + (
            risk === "LOW" ? "safe" :
            risk === "MODERATE" ? "warn" :
            "danger"
        );

        if (risk === "HIGH" || risk === "CRITICAL") {
            summaryEl.textContent = "PostGuard recommends that you do not publish this post.";
            decisionTitle.textContent = "🔴 DO NOT POST";
            decisionText.textContent = "Sensitive information was detected. Remove the items listed below and scan the post again before publishing.";
            decisionEl.style.borderColor = "#ff5f5f";
            decisionEl.style.background = "rgba(180,35,35,.14)";
        } else if (risk === "MODERATE") {
            summaryEl.textContent = "Review the findings before publishing.";
            decisionTitle.textContent = "🟠 REVIEW BEFORE POSTING";
            decisionText.textContent = "PostGuard found information worth reviewing. Check the recommendations below before publishing.";
            decisionEl.style.borderColor = "#d79b3d";
            decisionEl.style.background = "rgba(180,120,20,.12)";
        } else {
            summaryEl.textContent = "No major exposure was detected by the current PostGuard checks.";
            decisionTitle.textContent = "🟢 SAFE TO POST";
            decisionText.textContent = "No major security or privacy exposure was detected by the current PostGuard checks.";
            decisionEl.style.borderColor = "#4caf7d";
            decisionEl.style.background = "rgba(35,145,90,.12)";
        }

        const findings = data.findings || [];
        if (!findings.length) {
            findingsEl.innerHTML = '<div class="finding"><strong>No findings</strong><span class="muted">No specific risk rules were triggered.</span></div>';
            saferBox.style.display = "none";
        } else {
            findingsEl.innerHTML = findings.map(f => `
                <div class="finding">
                    <strong>${escapeHtml(f.category || f.title || "Security finding")}</strong>
                    <div>${escapeHtml(f.detail || "")}</div>
                    <div class="muted" style="margin-top:7px"><b>Recommended action:</b> ${escapeHtml(f.recommendation || "")}</div>
                </div>
            `).join("");

            saferCaptionEl.textContent = "Click Create Safer Post to keep the meaning of your post while removing risky details.";
            saferBox.style.display = "block";
        }
    } catch (error) {
        scoreEl.textContent = "--";
        riskEl.textContent = "Scan failed";
        riskEl.className = "status danger";
        summaryEl.textContent = error.message;
        decisionTitle.textContent = "SCAN COULD NOT COMPLETE";
        decisionText.textContent = error.message;
        decisionEl.style.borderColor = "#ff5f5f";
        decisionEl.style.background = "rgba(180,35,35,.14)";
    } finally {
        button.disabled = false;
        button.textContent = "Run PostGuard Check";
    }
});


generateSafer.addEventListener("click", async () => {
    const original = document.getElementById("caption").value.trim();

    if (!original) {
        saferCaptionEl.textContent = "Enter a caption first.";
        saferBox.style.display = "block";
        return;
    }

    generateSafer.disabled = true;
    generateSafer.textContent = "Creating safer post...";

    try {
        const payload = new FormData();
        payload.append(
            "csrf_token",
            form.querySelector('input[name="csrf_token"]').value
        );
        payload.append("caption", original);

        const response = await fetch("/api/safer-caption", {
            method: "POST",
            body: payload,
            credentials: "same-origin"
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Could not create a safer post.");
        }

        saferCaptionEl.textContent = data.safer_caption;
        saferBox.style.display = "block";
    } catch (error) {
        saferCaptionEl.textContent =
            error.message || "Could not create a safer post.";
        saferBox.style.display = "block";
    } finally {
        generateSafer.disabled = false;
        generateSafer.textContent = "Create Safer Post";
    }
});

rescanSafer.addEventListener("click", () => {
    const safer = saferCaptionEl.textContent.trim();

    if (!safer || safer.startsWith("Click Create")) {
        saferCaptionEl.textContent = "Generate a safer caption first.";
        return;
    }

    const sourceCheckId = originalRiskyCheckId || lastCheckId;

    if (!sourceCheckId) {
        saferCaptionEl.textContent = "Run the original post through PostGuard first.";
        return;
    }

    originalCheckField.value = String(sourceCheckId);
    saferCaptionField.value = safer;
    document.getElementById("caption").value = safer;
    form.requestSubmit();
});

copySafer.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(saferCaptionEl.textContent);
        copySafer.textContent = "Copied";
        setTimeout(() => { copySafer.textContent = "Copy safer caption"; }, 1200);
    } catch (_) {
        copySafer.textContent = "Select and copy the caption";
    }
});

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
}
</script>
</body>
</html>
"""


@app.get("/check-post")
@auth
def check_post():
    c = db()

    if session.get("role") == "admin":
        principals = c.execute(
            "SELECT * FROM principals ORDER BY id DESC"
        ).fetchall()
    else:
        principals = c.execute(
            """
            SELECT *
            FROM principals
            WHERE user_id=?
            ORDER BY id DESC
            """,
            (session["uid"],),
        ).fetchall()

    c.close()

    return render_template_string(
        CUSTOMER_CHECK_POST_PAGE,
        principals=principals,
    )



SCAN_HISTORY_DETAIL_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Scan Result</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09101d;color:#f5f7fb}
a{color:inherit}.main{max-width:1000px;margin:auto;padding:30px 20px}
.top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:22px}
.card{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.metric{background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:16px}
.metric .value{font-size:1.55rem;font-weight:800;margin-top:5px}
.muted{color:#95a4ba}.finding{background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:14px;margin-top:10px}
.btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;text-decoration:none;font-weight:700}
.decision{font-size:1.35rem;font-weight:850}
.safe{color:#7dd3a7}.warn{color:#f6c56f}.danger{color:#ff8c8c}
.caption{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<main class="main">
<div class="top">
    <div>
        <div class="muted">PostGuard scan history</div>
        <h1 style="margin:.2rem 0">Scan #{{ check['id'] }}</h1>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
        <a class="btn" href="{{ url_for('home') }}">Back to Dashboard</a>
        <form method="post" action="{{ url_for('logout') }}" style="margin:0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn" type="submit">Log out</button>
        </form>
    </div>
</div>

<div class="grid">
    <div class="metric"><div class="muted">Risk score</div><div class="value">{{ check['score'] }}/100</div></div>
    <div class="metric"><div class="muted">Risk level</div><div class="value">{{ check['risk'] }}</div></div>
    <div class="metric"><div class="muted">Checked</div><div class="value" style="font-size:1rem">{{ check['created_at'] }}</div></div>
</div>

<section class="card" style="margin-top:16px">
    {% if check['risk'] in ('HIGH','CRITICAL') %}
        <div class="decision danger">🔴 DO NOT POST</div>
        <p class="muted">This post contained high-risk information when it was checked.</p>
    {% elif check['risk'] == 'MODERATE' %}
        <div class="decision warn">🟠 REVIEW BEFORE POSTING</div>
        <p class="muted">Review the findings before publishing.</p>
    {% else %}
        <div class="decision safe">🟢 SAFE TO POST</div>
        <p class="muted">No major exposure was detected by the current PostGuard checks.</p>
    {% endif %}
</section>

<section class="card">
    <h2>Original caption</h2>
    <div class="caption">{{ check['caption'] or 'No caption was supplied.' }}</div>
</section>

{% if check['safer_caption'] %}
<section class="card">
    <h2>Safer caption</h2>
    <div class="caption">{{ check['safer_caption'] }}</div>

    {% if safer_check %}
    <div class="finding" style="margin-top:16px">
        <strong>Final re-scan result</strong>
        <div style="margin-top:8px">
            Score: <b>{{ safer_check['score'] }}/100</b>
            · Risk: <b>{{ safer_check['risk'] }}</b>
        </div>
        {% if safer_check['risk'] in ('HIGH','CRITICAL') %}
            <div class="danger" style="margin-top:8px;font-weight:800">🔴 DO NOT POST</div>
        {% elif safer_check['risk'] == 'MODERATE' %}
            <div class="warn" style="margin-top:8px;font-weight:800">🟠 REVIEW BEFORE POSTING</div>
        {% else %}
            <div class="safe" style="margin-top:8px;font-weight:800">🟢 SAFE TO POST</div>
        {% endif %}
        <div class="muted" style="margin-top:8px">Re-scanned {{ safer_check['created_at'] }}</div>
    </div>
    {% endif %}
</section>
{% endif %}

<section class="card">
    <h2>Findings</h2>
    {% if findings %}
        {% for f in findings %}
        <div class="finding">
            <strong>{{ f.get('category') or f.get('title') or 'Security finding' }}</strong>
            <div style="margin-top:6px">{{ f.get('detail','') }}</div>
            {% if f.get('recommendation') %}
            <div class="muted" style="margin-top:8px"><b>Recommended action:</b> {{ f.get('recommendation') }}</div>
            {% endif %}
        </div>
        {% endfor %}
    {% else %}
        <div class="finding">No specific risk findings were recorded.</div>
    {% endif %}
</section>

<div style="display:flex;gap:10px;flex-wrap:wrap">
    <a class="btn" href="{{ url_for('check_post') }}">Check another post</a>
    <a class="btn" href="{{ url_for('customer_cases_list') }}">My Cases</a>
        <a class="btn" href="{{ url_for('home') }}">Dashboard</a>
</div>
</main>
</body>
</html>
"""


@app.get("/scan-history/<int:check_id>")
@auth
def scan_history_detail(check_id):
    c = db()
    try:
        if session.get("role") == "admin":
            check = c.execute(
                "SELECT * FROM checks WHERE id=?",
                (check_id,),
            ).fetchone()
        else:
            check = c.execute(
                "SELECT * FROM checks WHERE id=? AND user_id=?",
                (check_id, session["uid"]),
            ).fetchone()

        safer_check = None
        if check and check["safer_check_id"]:
            if session.get("role") == "admin":
                safer_check = c.execute(
                    "SELECT * FROM checks WHERE id=?",
                    (check["safer_check_id"],),
                ).fetchone()
            else:
                safer_check = c.execute(
                    "SELECT * FROM checks WHERE id=? AND user_id=?",
                    (check["safer_check_id"], session["uid"]),
                ).fetchone()
    finally:
        c.close()

    if not check:
        abort(404)

    try:
        findings = json.loads(check["findings"] or "[]")
        if not isinstance(findings, list):
            findings = []
    except (TypeError, ValueError, json.JSONDecodeError):
        findings = []

    return render_template_string(
        SCAN_HISTORY_DETAIL_PAGE,
        check=check,
        findings=findings,
        safer_check=safer_check,
    )



def create_safer_caption(caption):
    """
    Create a safer rewrite that preserves the user's intended message
    while removing sensitive location, access, security and personal details.
    """
    original = (caption or "").strip()
    if not original:
        return ""

    safer = original

    # Replace specific sensitive details with natural, context-preserving wording.
    replacements = [
        # Access/security codes.
        (
            r"\b(the\s+)?(gate code|entry code|alarm code|passcode|password|pin)\s*(is|:)?\s*[A-Za-z0-9-]+\b",
            ""
        ),

        # Exact home/address disclosures.
        (
            r"\b(my|our)\s+(home|house|address)\s+(is|at)\s+[^,.!?]+",
            "I'm at home"
        ),
        (
            r"\b(address|postcode|post code|house number)\s*(is|:)?\s*[^,.!?]+",
            ""
        ),

        # Live-location phrasing: preserve the update but remove the live location.
        (
            r"\b(i am at|i'm at|currently at|here at|just arrived at|right now at|live from)\s+[^,.!?]+",
            "I'm enjoying the day"
        ),

        # Travel timing: remove precise timing while keeping the travel message.
        (
            r"\b(i'?m|we'?re|i am|we are)\s+(leaving|flying|travelling|traveling|going)\s+(today|tomorrow|tonight)\b",
            r"\1 looking forward to the trip"
        ),
        (
            r"\b(leaving|flying|travelling|traveling|going)\s+(today|tomorrow|tonight)\b",
            "looking forward to the trip"
        ),

        # Security arrangements.
        (
            r"\b(my|our)\s+(security|bodyguard|guard|security team)\s+(is|are)\s+[^,.!?]+",
            ""
        ),
        (
            r"\b(alarm|camera|cctv)\s+(is|are)\s+(off|disabled|broken|not working)\b",
            ""
        ),
    ]

    for pattern, replacement in replacements:
        safer = re.sub(pattern, replacement, safer, flags=re.I)

    # Remove obvious long numeric codes that remain near risky words.
    safer = re.sub(
        r"\b(code|pin|passcode|password)\b[^.!?]{0,15}\b\d{3,10}\b",
        "",
        safer,
        flags=re.I,
    )

    # Clean punctuation and whitespace.
    safer = re.sub(r"\s{2,}", " ", safer)
    safer = re.sub(r"\s+([,.!?])", r"\1", safer)
    safer = re.sub(r"([.!?]){2,}", r"\1", safer)
    safer = safer.strip(" \t\r\n,.;:-")

    # Improve a few common fragments after redaction.
    safer = re.sub(r"\bI'm home now\b", "Home and relaxing now", safer, flags=re.I)
    safer = re.sub(r"\bI am home now\b", "Home and relaxing now", safer, flags=re.I)
    safer = re.sub(r"\bwe're home now\b", "Home and relaxing now", safer, flags=re.I)

    # If only a fragment remains, create a natural rewrite using the context.
    if len(safer) < 8:
        lower = original.lower()

        if any(word in lower for word in ("home", "house", "gate", "alarm")):
            safer = "Home and relaxing now — keeping the security details private."
        elif any(word in lower for word in ("holiday", "trip", "flight", "airport", "travel")):
            safer = "Looking forward to the trip — I'll share more once we're back."
        elif any(word in lower for word in ("concert", "stadium", "restaurant", "hotel", "venue")):
            safer = "Having a great time today — sharing the details after I leave."
        else:
            safer = "Sharing an update while keeping private details offline."

    # If the risky caption survived substantially unchanged, return a
    # context-aware alternative rather than a generic warning sentence.
    if safer.lower() == original.lower():
        lower = original.lower()

        if any(word in lower for word in ("home", "house", "gate", "alarm", "security")):
            safer = "Home and relaxing now — keeping the security details private."
        elif any(word in lower for word in ("holiday", "trip", "flight", "airport", "travel")):
            safer = "Looking forward to the trip — I'll share the details afterwards."
        elif any(word in lower for word in ("family", "children", "kids", "school")):
            safer = "Lovely family time today — keeping the personal details private."
        elif any(word in lower for word in ("car", "vehicle", "number plate", "registration")):
            safer = "Great day out — keeping the vehicle details private."
        else:
            safer = "Sharing an update while keeping private details offline."

    return safer


@app.post("/api/safer-caption")
@auth
@limiter.limit("20 per minute")
def api_safer_caption():
    caption = request.form.get("caption", "").strip()

    if not caption:
        return jsonify(error="Enter a caption first."), 400

    safer = create_safer_caption(caption)

    return jsonify(
        safer_caption=safer,
    )


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

    original_check_id_raw = request.form.get(
        "original_check_id",
        "",
    ).strip()

    safer_caption = request.form.get(
        "safer_caption",
        "",
    ).strip()

    original_check_id = None
    if original_check_id_raw:
        try:
            original_check_id = int(original_check_id_raw)
        except ValueError:
            return jsonify(error="Invalid original scan reference."), 400

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

            if original_check_id and safer_caption:
                if session.get("role") == "admin":
                    original_row = c.execute(
                        "SELECT id FROM checks WHERE id=?",
                        (original_check_id,),
                    ).fetchone()
                else:
                    original_row = c.execute(
                        "SELECT id FROM checks WHERE id=? AND user_id=?",
                        (original_check_id, session["uid"]),
                    ).fetchone()

                if original_row:
                    if session.get("role") == "admin":
                        c.execute(
                            """
                            UPDATE checks
                            SET safer_caption=?, safer_check_id=?
                            WHERE id=?
                            """,
                            (safer_caption, check_id, original_check_id),
                        )
                    else:
                        c.execute(
                            """
                            UPDATE checks
                            SET safer_caption=?, safer_check_id=?
                            WHERE id=? AND user_id=?
                            """,
                            (
                                safer_caption,
                                check_id,
                                original_check_id,
                                session["uid"],
                            ),
                        )

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
            check_id=check_id,
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



CUSTOMER_ALERT_DETAIL_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Alert</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09101d;color:#f5f7fb}
a{color:inherit}.main{max-width:1000px;margin:auto;padding:30px 20px}
.top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:22px}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.card{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.metric{background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:16px}
.metric .value{font-size:1.2rem;font-weight:800;margin-top:5px;overflow-wrap:anywhere}
.muted{color:#95a4ba}.danger{color:#ff8c8c}.warn{color:#f6c56f}.safe{color:#7dd3a7}
.btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;text-decoration:none;font-weight:700;cursor:pointer}
.finding{background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:14px;margin-top:10px}
.caption{white-space:pre-wrap;overflow-wrap:anywhere}
.severity{font-size:1.35rem;font-weight:850}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<main class="main">
<div class="top">
    <div>
        <div class="muted">PostGuard customer alert</div>
        <h1 style="margin:.2rem 0">Alert #{{ alert['id'] }}</h1>
    </div>
    <div class="actions">
        <a class="btn" href="{{ url_for('home') }}">Back to Dashboard</a>
        <form method="post" action="{{ url_for('logout') }}" style="margin:0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn" type="submit">Log out</button>
        </form>
    </div>
</div>

<section class="card">
    {% if alert['severity'] in ('HIGH','CRITICAL') %}
        <div class="severity danger">🔴 {{ alert['severity'] }} RISK ALERT</div>
    {% elif alert['severity'] == 'MODERATE' %}
        <div class="severity warn">🟠 MODERATE RISK ALERT</div>
    {% else %}
        <div class="severity safe">🟢 {{ alert['severity'] or 'LOW' }} RISK</div>
    {% endif %}
    <p class="muted">{{ alert['category'] or 'PostGuard security alert' }}</p>
</section>

<div class="grid">
    <div class="metric"><div class="muted">Status</div><div class="value">{{ alert['status'] or 'Open' }}</div></div>
    <div class="metric"><div class="muted">Risk score</div><div class="value">{{ alert['risk_score'] if alert['risk_score'] is not none else '—' }}</div></div>
    <div class="metric"><div class="muted">Created</div><div class="value" style="font-size:1rem">{{ alert['created_at'] }}</div></div>
</div>

<section class="card" style="margin-top:16px">
    <h2>Why this was flagged</h2>
    <div>{{ alert['detail'] or 'This post triggered a PostGuard risk alert.' }}</div>
</section>

<section class="card">
    <h2>Recommended action</h2>
    <div>{{ alert['recommendation'] or 'Review and remove sensitive information before publishing.' }}</div>
</section>

{% if alert['caption'] %}
<section class="card">
    <h2>Caption that triggered the alert</h2>
    <div class="caption">{{ alert['caption'] }}</div>
</section>
{% endif %}

{% if check %}
<section class="card">
    <h2>Triggering scan</h2>
    <div class="finding">
        <strong>Score {{ check['score'] }}/100 · {{ check['risk'] }}</strong>
        <div class="muted" style="margin-top:7px">Checked {{ check['created_at'] }}</div>
        <div style="margin-top:12px">
            <a class="btn" href="{{ url_for('scan_history_detail', check_id=check['id']) }}">Open full scan result</a>
        </div>
    </div>
</section>

{% if check['safer_caption'] %}
<section class="card">
    <h2>Safer version created</h2>
    <div class="caption">{{ check['safer_caption'] }}</div>

    {% if safer_check %}
    <div class="finding" style="margin-top:14px">
        <strong>Safer re-scan: {{ safer_check['score'] }}/100 · {{ safer_check['risk'] }}</strong>
        {% if safer_check['risk'] in ('HIGH','CRITICAL') %}
            <div class="danger" style="margin-top:7px;font-weight:800">🔴 DO NOT POST</div>
        {% elif safer_check['risk'] == 'MODERATE' %}
            <div class="warn" style="margin-top:7px;font-weight:800">🟠 REVIEW BEFORE POSTING</div>
        {% else %}
            <div class="safe" style="margin-top:7px;font-weight:800">🟢 SAFE TO POST</div>
        {% endif %}
    </div>
    {% endif %}
</section>
{% endif %}
{% endif %}

<div class="actions">
    <a class="btn" href="{{ url_for('check_post') }}">Check another post</a>
    {% if check %}
    <a class="btn" href="{{ url_for('scan_history_detail', check_id=check['id']) }}">View scan history</a>
    {% endif %}
    <form method="post" action="{{ url_for('customer_create_case_from_alert', alert_id=alert['id']) }}" style="margin:0">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button class="btn" type="submit">Create / Open Case</button>
    </form>
</div>
</main>
</body>
</html>
"""


@app.get("/alerts/<int:alert_id>")
@auth
def customer_alert_detail(alert_id):
    c = db()
    try:
        if session.get("role") == "admin":
            alert = c.execute(
                "SELECT * FROM alerts WHERE id=?",
                (alert_id,),
            ).fetchone()
        else:
            alert = c.execute(
                "SELECT * FROM alerts WHERE id=? AND user_id=?",
                (alert_id, session["uid"]),
            ).fetchone()

        if not alert:
            abort(404)

        check = None
        safer_check = None

        if alert["check_id"]:
            if session.get("role") == "admin":
                check = c.execute(
                    "SELECT * FROM checks WHERE id=?",
                    (alert["check_id"],),
                ).fetchone()
            else:
                check = c.execute(
                    "SELECT * FROM checks WHERE id=? AND user_id=?",
                    (alert["check_id"], session["uid"]),
                ).fetchone()

        if check and check["safer_check_id"]:
            if session.get("role") == "admin":
                safer_check = c.execute(
                    "SELECT * FROM checks WHERE id=?",
                    (check["safer_check_id"],),
                ).fetchone()
            else:
                safer_check = c.execute(
                    "SELECT * FROM checks WHERE id=? AND user_id=?",
                    (check["safer_check_id"], session["uid"]),
                ).fetchone()
    finally:
        c.close()

    return render_template_string(
        CUSTOMER_ALERT_DETAIL_PAGE,
        alert=alert,
        check=check,
        safer_check=safer_check,
    )


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



CUSTOMER_CASE_DETAIL_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Case</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09101d;color:#f5f7fb}
a{color:inherit}.main{max-width:1000px;margin:auto;padding:30px 20px}
.top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:22px}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.card{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.metric{background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:16px}
.metric .value{font-size:1.15rem;font-weight:800;margin-top:5px;overflow-wrap:anywhere}
.muted{color:#95a4ba}.danger{color:#ff8c8c}.warn{color:#f6c56f}.safe{color:#7dd3a7}
.btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;text-decoration:none;font-weight:700;cursor:pointer}
textarea,select{width:100%;padding:12px;border-radius:10px;border:1px solid #31415e;background:#0d1525;color:#fff}
label{display:block;font-weight:700;margin-bottom:7px}
.field{margin-top:14px}
.caption{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<main class="main">
<div class="top">
    <div>
        <div class="muted">PostGuard customer case</div>
        <h1 style="margin:.2rem 0">Case #{{ case['id'] }}</h1>
    </div>
    <div class="actions">
        <a class="btn" href="{{ url_for('home') }}">Dashboard</a>
        <form method="post" action="{{ url_for('logout') }}" style="margin:0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn" type="submit">Log out</button>
        </form>
    </div>
</div>

<div class="grid">
    <div class="metric"><div class="muted">Status</div><div class="value">{{ case['status'] or 'Open' }}</div></div>
    <div class="metric"><div class="muted">Severity</div><div class="value">{{ case['severity'] or '—' }}</div></div>
    <div class="metric"><div class="muted">Created</div><div class="value" style="font-size:1rem">{{ case['created_at'] }}</div></div>
</div>

<section class="card" style="margin-top:16px">
    <h2>{{ case['title'] or 'Security case' }}</h2>
    <div class="muted">{{ case['category'] or 'PostGuard incident management' }}</div>
    {% if case['notes'] %}
    <div class="caption" style="margin-top:14px">{{ case['notes'] }}</div>
    {% endif %}
</section>

{% if alert %}
<section class="card">
    <h2>Linked alert</h2>
    <div><b>{{ alert['severity'] }}</b> · {{ alert['category'] }}</div>
    <div class="muted" style="margin-top:6px">{{ alert['created_at'] }}</div>
    <div style="margin-top:12px">
        <a class="btn" href="{{ url_for('customer_alert_detail', alert_id=alert['id']) }}">Open alert</a>
    </div>
</section>
{% endif %}

{% if check %}
<section class="card">
    <h2>Linked scan</h2>
    <div><b>{{ check['score'] }}/100 · {{ check['risk'] }}</b></div>
    <div class="caption" style="margin-top:10px">{{ check['caption'] or 'No caption supplied.' }}</div>
    <div style="margin-top:12px">
        <a class="btn" href="{{ url_for('scan_history_detail', check_id=check['id']) }}">Open scan</a>
    </div>
</section>
{% endif %}

<section class="card">
    <h2>Update case</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <div class="field">
            <label for="status">Status</label>
            <select id="status" name="status">
                {% for option in ('Open','Investigating','Monitoring','Resolved','Closed') %}
                <option value="{{ option }}" {% if case['status']==option %}selected{% endif %}>{{ option }}</option>
                {% endfor %}
            </select>
        </div>

        <div class="field">
            <label for="notes">Case notes</label>
            <textarea id="notes" name="notes" rows="7" placeholder="Add investigation notes, actions taken or resolution details...">{{ case['notes'] or '' }}</textarea>
        </div>

        <div class="actions" style="margin-top:14px">
            <button class="btn" type="submit">Save case</button>
        </div>
    </form>
</section>
</main>
</body>
</html>
"""


@app.post("/alerts/<int:alert_id>/create-case")
@auth
@limiter.limit("10 per minute")
def customer_create_case_from_alert(alert_id):
    c = db()
    try:
        if session.get("role") == "admin":
            alert = c.execute(
                "SELECT * FROM alerts WHERE id=?",
                (alert_id,),
            ).fetchone()
        else:
            alert = c.execute(
                "SELECT * FROM alerts WHERE id=? AND user_id=?",
                (alert_id, session["uid"]),
            ).fetchone()

        if not alert:
            abort(404)

        existing = c.execute(
            "SELECT * FROM cases WHERE alert_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
            (alert_id, alert["user_id"]),
        ).fetchone()

        if existing:
            return redirect(url_for("customer_case_detail", case_id=existing["id"]))

        title = f"{alert['category'] or 'Security'} alert"
        notes = (
            "Created from PostGuard alert. "
            + (alert["recommendation"] or "Review the alert and record actions taken.")
        )

        case_row = c.execute(
            """
            INSERT INTO cases(
                user_id,
                principal_id,
                alert_id,
                title,
                category,
                severity,
                status,
                notes,
                created_at
            )
            VALUES(?,?,?,?,?,?,?,?,?)
            RETURNING *
            """,
            (
                alert["user_id"],
                alert["principal_id"],
                alert["id"],
                title,
                alert["category"],
                alert["severity"],
                "Open",
                notes,
                now(),
            ),
        ).fetchone()

        c.execute(
            "UPDATE alerts SET status='In Case' WHERE id=?",
            (alert_id,),
        )
        c.commit()

        return redirect(url_for("customer_case_detail", case_id=case_row["id"]))
    finally:
        c.close()


@app.route("/cases/<int:case_id>", methods=["GET", "POST"])
@auth
@limiter.limit("20 per minute")
def customer_case_detail(case_id):
    c = db()
    try:
        if session.get("role") == "admin":
            case = c.execute(
                "SELECT * FROM cases WHERE id=?",
                (case_id,),
            ).fetchone()
        else:
            case = c.execute(
                "SELECT * FROM cases WHERE id=? AND user_id=?",
                (case_id, session["uid"]),
            ).fetchone()

        if not case:
            abort(404)

        if request.method == "POST":
            allowed_statuses = {
                "Open",
                "Investigating",
                "Monitoring",
                "Resolved",
                "Closed",
            }
            status = request.form.get("status", "Open").strip()
            notes = request.form.get("notes", "").strip()

            if status not in allowed_statuses:
                return "Invalid case status", 400

            if session.get("role") == "admin":
                c.execute(
                    "UPDATE cases SET status=?, notes=? WHERE id=?",
                    (status, notes, case_id),
                )
            else:
                c.execute(
                    "UPDATE cases SET status=?, notes=? WHERE id=? AND user_id=?",
                    (status, notes, case_id, session["uid"]),
                )

            if case["alert_id"]:
                alert_status = "Resolved" if status in ("Resolved", "Closed") else "In Case"
                c.execute(
                    "UPDATE alerts SET status=? WHERE id=?",
                    (alert_status, case["alert_id"]),
                )

            c.commit()

            if session.get("role") == "admin":
                case = c.execute(
                    "SELECT * FROM cases WHERE id=?",
                    (case_id,),
                ).fetchone()
            else:
                case = c.execute(
                    "SELECT * FROM cases WHERE id=? AND user_id=?",
                    (case_id, session["uid"]),
                ).fetchone()

        alert = None
        check = None

        if case["alert_id"]:
            if session.get("role") == "admin":
                alert = c.execute(
                    "SELECT * FROM alerts WHERE id=?",
                    (case["alert_id"],),
                ).fetchone()
            else:
                alert = c.execute(
                    "SELECT * FROM alerts WHERE id=? AND user_id=?",
                    (case["alert_id"], session["uid"]),
                ).fetchone()

        if alert and alert["check_id"]:
            if session.get("role") == "admin":
                check = c.execute(
                    "SELECT * FROM checks WHERE id=?",
                    (alert["check_id"],),
                ).fetchone()
            else:
                check = c.execute(
                    "SELECT * FROM checks WHERE id=? AND user_id=?",
                    (alert["check_id"], session["uid"]),
                ).fetchone()
    finally:
        c.close()

    return render_template_string(
        CUSTOMER_CASE_DETAIL_PAGE,
        case=case,
        alert=alert,
        check=check,
    )



CUSTOMER_CASES_LIST_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · My Cases</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09101d;color:#f5f7fb}
a{color:inherit}.main{max-width:1100px;margin:auto;padding:30px 20px}
.top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:22px}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.card{background:#111a2b;border:1px solid #22304a;border-radius:16px;padding:20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.metric{background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:16px}
.metric .value{font-size:1.5rem;font-weight:800;margin-top:5px}
.muted{color:#95a4ba}.btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #31415e;background:#151f33;color:#fff;text-decoration:none;font-weight:700;cursor:pointer}
.case{display:block;background:#0d1525;border:1px solid #2c3a55;border-radius:12px;padding:16px;text-decoration:none;margin-top:10px}
.case:hover{border-color:#4b5f86}
.row{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;flex-wrap:wrap}
.badge{padding:5px 9px;border-radius:999px;border:1px solid #33435f;font-size:.83rem;font-weight:800}
.open{color:#ffb1b1}.investigating{color:#ffd27a}.monitoring{color:#9ec8ff}.resolved,.closed{color:#8ee0b5}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.filters a{padding:8px 11px;border-radius:9px;border:1px solid #31415e;text-decoration:none}
@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:500px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<main class="main">
<div class="top">
    <div>
        <div class="muted">PostGuard incident management</div>
        <h1 style="margin:.2rem 0">My Cases</h1>
    </div>
    <div class="actions">
        <a class="btn" href="{{ url_for('home') }}">Dashboard</a>
        <a class="btn" href="{{ url_for('check_post') }}">Check a Post</a>
        <form method="post" action="{{ url_for('logout') }}" style="margin:0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn" type="submit">Log out</button>
        </form>
    </div>
</div>

<div class="grid">
    <div class="metric"><div class="muted">Open</div><div class="value">{{ counts['Open'] }}</div></div>
    <div class="metric"><div class="muted">Investigating</div><div class="value">{{ counts['Investigating'] }}</div></div>
    <div class="metric"><div class="muted">Monitoring</div><div class="value">{{ counts['Monitoring'] }}</div></div>
    <div class="metric"><div class="muted">Resolved / Closed</div><div class="value">{{ counts['Resolved'] + counts['Closed'] }}</div></div>
</div>

<section class="card" style="margin-top:16px">
    <div class="row">
        <div>
            <h2 style="margin:0">Cases</h2>
            <div class="muted">Open a case to review notes, linked alerts and status.</div>
        </div>
        <div class="filters">
            <a href="{{ url_for('customer_cases_list') }}">All</a>
            <a href="{{ url_for('customer_cases_list', status='Open') }}">Open</a>
            <a href="{{ url_for('customer_cases_list', status='Investigating') }}">Investigating</a>
            <a href="{{ url_for('customer_cases_list', status='Monitoring') }}">Monitoring</a>
            <a href="{{ url_for('customer_cases_list', status='Resolved') }}">Resolved</a>
            <a href="{{ url_for('customer_cases_list', status='Closed') }}">Closed</a>
        </div>
    </div>

    {% if cases %}
        {% for row in cases %}
        <a class="case" href="{{ url_for('customer_case_detail', case_id=row['id']) }}">
            <div class="row">
                <div>
                    <strong>{{ row['title'] or ('Case #' ~ row['id']) }}</strong>
                    <div class="muted" style="margin-top:6px">
                        {{ row['category'] or 'Security case' }}
                        {% if row['severity'] %} · {{ row['severity'] }}{% endif %}
                    </div>
                    <div class="muted" style="margin-top:4px">{{ row['created_at'] }}</div>
                </div>
                <span class="badge {{ (row['status'] or 'Open')|lower }}">{{ row['status'] or 'Open' }}</span>
            </div>
        </a>
        {% endfor %}
    {% else %}
        <div class="case">
            <strong>No cases found</strong>
            <div class="muted" style="margin-top:6px">Create a case from a customer alert when follow-up is needed.</div>
        </div>
    {% endif %}
</section>
</main>
</body>
</html>
"""


@app.get("/my-cases")
@auth
def customer_cases_list():
    requested_status = request.args.get("status", "").strip()
    allowed_statuses = {"Open", "Investigating", "Monitoring", "Resolved", "Closed"}

    if requested_status and requested_status not in allowed_statuses:
        requested_status = ""

    c = db()
    try:
        if session.get("role") == "admin":
            if requested_status:
                cases = c.execute(
                    "SELECT * FROM cases WHERE status=? ORDER BY id DESC",
                    (requested_status,),
                ).fetchall()
            else:
                cases = c.execute(
                    "SELECT * FROM cases ORDER BY id DESC"
                ).fetchall()

            rows = c.execute(
                "SELECT status, COUNT(*) AS total FROM cases GROUP BY status"
            ).fetchall()
        else:
            if requested_status:
                cases = c.execute(
                    "SELECT * FROM cases WHERE user_id=? AND status=? ORDER BY id DESC",
                    (session["uid"], requested_status),
                ).fetchall()
            else:
                cases = c.execute(
                    "SELECT * FROM cases WHERE user_id=? ORDER BY id DESC",
                    (session["uid"],),
                ).fetchall()

            rows = c.execute(
                "SELECT status, COUNT(*) AS total FROM cases WHERE user_id=? GROUP BY status",
                (session["uid"],),
            ).fetchall()
    finally:
        c.close()

    counts = {
        "Open": 0,
        "Investigating": 0,
        "Monitoring": 0,
        "Resolved": 0,
        "Closed": 0,
    }
    for row in rows:
        status = row["status"] or "Open"
        if status in counts:
            counts[status] = row["total"]

    return render_template_string(
        CUSTOMER_CASES_LIST_PAGE,
        cases=cases,
        counts=counts,
        requested_status=requested_status,
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
# FORCED CUSTOMER PASSWORD RESET
# ============================================================

FORCED_PASSWORD_RESET_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>PostGuard · Reset Password</title>
    <style>
        :root{color-scheme:dark}
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;display:grid;place-items:center;
             font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb;padding:24px}
        .panel{width:min(520px,100%);background:#151c2f;border:1px solid #26314a;
               border-radius:16px;padding:28px}
        h1{margin-top:0}
        .muted{color:#aeb9ce;line-height:1.5}
        label{display:block;margin:18px 0 7px}
        input{width:100%;padding:12px;border-radius:9px;border:1px solid #394762;
              background:#0b1020;color:#f5f7fb}
        button{width:100%;margin-top:22px;padding:12px;border-radius:9px;
               border:1px solid #4c5f82;background:#1b2742;color:#fff;cursor:pointer}
        .flash{padding:10px 12px;border:1px solid #7b3540;border-radius:9px;margin:12px 0}
    </style>
</head>
<body>
<div class="panel">
    <h1>Password reset required</h1>
    <p class="muted">
        An administrator has required a password reset for {{ session.get("email") }}.
        Choose a new password before continuing to PostGuard.
    </p>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="flash">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <label for="password">New password</label>
        <input id="password" name="password" type="password"
               minlength="12" autocomplete="new-password" required>

        <label for="confirm_password">Confirm new password</label>
        <input id="confirm_password" name="confirm_password" type="password"
               minlength="12" autocomplete="new-password" required>

        <button type="submit">Set new password</button>
    </form>
</div>
</body>
</html>
"""


@app.route("/account/reset-password", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def forced_password_reset():
    if "uid" not in session:
        return redirect(url_for("login"))

    c = db()
    user = c.execute(
        """
        SELECT id, email, password, role, enabled, reset_required
        FROM users
        WHERE id=?
        """,
        (session["uid"],),
    ).fetchone()

    if not user:
        c.close()
        session.clear()
        return redirect(url_for("login"))

    if user["enabled"] == 0 and user["role"] != "admin":
        c.close()
        session.clear()
        flash("This PostGuard account has been disabled by an administrator.")
        return redirect(url_for("login"))

    if user["role"] == "admin" or user["reset_required"] != 1:
        c.close()
        return redirect(url_for("home"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 12:
            c.close()
            flash("Your new password must be at least 12 characters.")
            return render_template_string(FORCED_PASSWORD_RESET_PAGE), 400

        if password != confirm_password:
            c.close()
            flash("The new passwords do not match.")
            return render_template_string(FORCED_PASSWORD_RESET_PAGE), 400

        if check_password_hash(user["password"], password):
            c.close()
            flash("Choose a password different from your current password.")
            return render_template_string(FORCED_PASSWORD_RESET_PAGE), 400

        c.execute(
            """
            UPDATE users
            SET password=?, reset_required=0
            WHERE id=?
            """,
            (
                generate_password_hash(password),
                user["id"],
            ),
        )
        c.commit()
        c.close()

        audit("forced_password_reset_complete", f"user_id={user['id']}")
        session.clear()
        flash("Password changed successfully. Sign in with your new password.")
        return redirect(url_for("login"))

    c.close()
    return render_template_string(FORCED_PASSWORD_RESET_PAGE)



# ============================================================
# CUSTOMER ACCOUNT CENTRE
# ============================================================

ACCOUNT_PAGE = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · My Account</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}
main{width:min(760px,calc(100% - 32px));margin:40px auto}.card{background:#151c2f;border:1px solid #26314a;border-radius:16px;padding:24px;margin:16px 0}
.muted{color:#aeb9ce}.btn{display:inline-block;padding:10px 13px;border:1px solid #394762;border-radius:9px;background:#151c2f;color:#fff;text-decoration:none;cursor:pointer}
.danger{border-color:#a54251;background:#381720}label{display:block;margin:15px 0 6px}input{width:100%;padding:12px;border-radius:9px;border:1px solid #394762;background:#0b1020;color:#fff}
.flash{padding:10px 12px;border:1px solid #4c5f82;border-radius:9px;margin:12px 0}.actions{display:flex;gap:10px;flex-wrap:wrap}
</style></head><body><main>
<div class="actions">
<a class="btn" href="{{ url_for('home') }}">← Dashboard</a>
<form method="post" action="{{ url_for('logout') }}" style="margin:0">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button class="btn" type="submit">Log out</button>
</form>
</div>
<h1>My Account</h1>
{% with messages=get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<div class="card"><h2>Account details</h2><p><strong>Email:</strong> {{ user["email"] }}</p><p><strong>Account type:</strong> {{ user["role"] or "user" }}</p><p><strong>Registered:</strong> {{ user["created_at"] or "—" }}</p></div>
<div class="card"><h2>Change password</h2>
<form method="post" action="{{ url_for('account_change_password') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Current password</label><input name="current_password" type="password" autocomplete="current-password" required>
<label>New password</label><input name="new_password" type="password" minlength="12" autocomplete="new-password" required>
<label>Confirm new password</label><input name="confirm_password" type="password" minlength="12" autocomplete="new-password" required>
<button class="btn" type="submit" style="margin-top:18px">Change password</button></form></div>
{% if user["role"] != "admin" %}
<div class="card"><h2>Delete my account</h2><p class="muted">Permanently removes your PostGuard account and PostGuard-owned scans, alerts, cases and profile records.</p>
<a class="btn danger" href="{{ url_for('account_delete') }}">Delete my account</a></div>
{% endif %}
</main></body></html>
"""

ACCOUNT_DELETE_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · Delete Account</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}
.panel{width:min(600px,100%);background:#151c2f;border:1px solid #7b3540;border-radius:16px;padding:28px}.warning{line-height:1.5}.muted{color:#aeb9ce}
label{display:block;margin:16px 0 6px}input{width:100%;padding:12px;border-radius:9px;border:1px solid #394762;background:#0b1020;color:#fff}
.btn{display:inline-block;margin-top:18px;padding:11px 14px;border-radius:9px;border:1px solid #394762;background:#151c2f;color:#fff;text-decoration:none;cursor:pointer}.danger{border-color:#a54251;background:#381720}
</style></head><body><div class="panel"><h1>Delete my account</h1>
<p class="warning"><strong>This is permanent.</strong> Your PostGuard account and PostGuard-owned customer data will be deleted.</p>
<p class="muted">To confirm, type your email address and current password.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Email</label><input name="confirm_email" type="email" autocomplete="off" required>
<label>Current password</label><input name="password" type="password" autocomplete="current-password" required>
<button class="btn danger" type="submit" onclick="return confirm('Permanently delete your PostGuard account?')">Permanently delete my account</button>
<a class="btn" href="{{ url_for('account') }}">Cancel</a></form></div></body></html>
"""

@app.get("/account")
@auth
def account():
    c=db()
    user=c.execute("SELECT id,email,role,created_at FROM users WHERE id=?",(session["uid"],)).fetchone()
    c.close()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    return render_template_string(ACCOUNT_PAGE,user=user)

@app.post("/account/change-password")
@auth
@limiter.limit("5 per minute")
def account_change_password():
    current=request.form.get("current_password","")
    new=request.form.get("new_password","")
    confirm=request.form.get("confirm_password","")
    c=db()
    user=c.execute("SELECT id,password FROM users WHERE id=?",(session["uid"],)).fetchone()
    if not user or not check_password_hash(user["password"],current):
        c.close(); flash("Current password is incorrect."); return redirect(url_for("account"))
    if len(new)<12:
        c.close(); flash("New password must be at least 12 characters."); return redirect(url_for("account"))
    if new!=confirm:
        c.close(); flash("New passwords do not match."); return redirect(url_for("account"))
    if check_password_hash(user["password"],new):
        c.close(); flash("Choose a password different from your current password."); return redirect(url_for("account"))
    c.execute("UPDATE users SET password=?,reset_required=0 WHERE id=?",(generate_password_hash(new),user["id"]))
    c.commit(); c.close()
    audit("customer_password_change",f"user_id={user['id']}")
    session.clear()
    flash("Password changed. Sign in again with your new password.")
    return redirect(url_for("login"))

@app.route("/account/delete",methods=["GET","POST"])
@auth
@limiter.limit("5 per minute",methods=["POST"])
def account_delete():
    uid=session["uid"]
    c=db()
    user=c.execute("SELECT id,email,password,role FROM users WHERE id=?",(uid,)).fetchone()
    if not user:
        c.close(); session.clear(); return redirect(url_for("login"))
    if (user["role"] or "user")=="admin":
        c.close(); abort(403)
    if request.method=="POST":
        email=request.form.get("confirm_email","").strip().lower()
        password=request.form.get("password","")
        if email!=user["email"].strip().lower() or not check_password_hash(user["password"],password):
            c.close(); flash("Email or password confirmation was incorrect."); return render_template_string(ACCOUNT_DELETE_PAGE),403
        c.execute("DELETE FROM alerts WHERE user_id=?",(uid,))
        c.execute("DELETE FROM cases WHERE user_id=?",(uid,))
        c.execute("DELETE FROM checks WHERE user_id=?",(uid,))
        c.execute("DELETE FROM principals WHERE user_id=?",(uid,))
        c.execute("DELETE FROM audit WHERE user_id=?",(uid,))
        c.execute("DELETE FROM users WHERE id=?",(uid,))
        c.commit(); c.close()
        session.clear()
        flash("Your PostGuard account has been permanently deleted.")
        return redirect(url_for("login"))
    c.close()
    return render_template_string(ACCOUNT_DELETE_PAGE)

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
<div class="table"><table><thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Status</th><th>Password</th><th>Registered</th><th>Scans</th><th>Alerts</th><th>Cases</th><th>Controls</th></tr></thead><tbody>
{% for user in users %}<tr class="{% if user['enabled']==0 %}disabled{% endif %}"><td>{{ user['id'] }}</td><td>{{ user['email'] }}</td><td><span class="pill">{{ user['role'] or 'user' }}</span></td><td><span class="pill">{{ 'Enabled' if user['enabled'] != 0 else 'Disabled' }}</span></td><td><span class="pill">{{ 'Reset required' if user['reset_required']==1 else 'Current' }}</span></td><td>{{ user['created_at'] or '—' }}</td><td>{{ user['check_count'] }}</td><td>{{ user['alert_count'] }}</td><td>{{ user['case_count'] }}</td><td>{% if user['role'] != 'admin' %}<a class="btn" href="{{ url_for('admin_user_detail',user_id=user['id']) }}">View</a> <form class="inline" method="post" action="{{ url_for('admin_force_password_reset',user_id=user['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn" onclick="return confirm('Require this customer to change their password at next sign-in?')">Force password reset</button></form> <a class="btn danger" href="{{ url_for('admin_delete_user',user_id=user['id']) }}">Delete</a> {% if user['enabled']==0 %}<form class="inline" method="post" action="{{ url_for('admin_enable_user',user_id=user['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn success">Enable</button></form>{% else %}<form class="inline" method="post" action="{{ url_for('admin_disable_user',user_id=user['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn danger" onclick="return confirm('Disable this customer account?')">Disable</button></form>{% endif %}{% else %}<span class="muted">Protected admin</span>{% endif %}</td></tr>{% else %}<tr><td colspan="9">No users found.</td></tr>{% endfor %}
</tbody></table></div><p class="muted">Passwords are never displayed. Disabling a customer blocks login and invalidates their active session on its next request.</p></main></body></html>
"""

ADMIN_USER_DETAIL_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PostGuard Admin · Customer</title><style>:root{color-scheme:dark}body{margin:0;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}header,main{padding:24px 28px}header{border-bottom:1px solid #26314a}.muted{color:#aeb9ce}.btn{display:inline-block;padding:8px 11px;border:1px solid #394762;border-radius:8px;background:#151c2f;color:inherit;text-decoration:none}.table{overflow-x:auto;background:#151c2f;border:1px solid #26314a;border-radius:14px;margin:12px 0 24px}table{width:100%;border-collapse:collapse;min-width:720px}th,td{padding:11px 13px;text-align:left;border-bottom:1px solid #26314a}th{color:#aeb9ce;font-size:.8rem;text-transform:uppercase}</style></head><body>
<header><a class="btn" href="{{ url_for('admin_users') }}">← Registered Users</a> <a class="btn" href="{{ url_for('admin_delete_user',user_id=user['id']) }}">Delete account</a><h1>{{ user['email'] }}</h1><div class="muted">{{ user['role'] or 'user' }} · {{ 'Enabled' if user['enabled'] != 0 else 'Disabled' }} · {{ 'Password reset required' if user['reset_required']==1 else 'Password current' }} · Registered {{ user['created_at'] or '—' }}</div></header><main>
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
        SELECT u.id,u.email,u.role,u.enabled,u.reset_required,u.created_at,
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



ADMIN_DELETE_USER_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>PostGuard Admin · Delete Customer</title>
    <style>
        :root{color-scheme:dark}
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;display:grid;place-items:center;
             padding:24px;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}
        .panel{width:min(620px,100%);background:#151c2f;border:1px solid #49303a;
               border-radius:16px;padding:28px}
        .warning{padding:14px;border:1px solid #7b3540;border-radius:10px;
                 background:#20131a;line-height:1.5}
        .muted{color:#aeb9ce;line-height:1.5}
        label{display:block;margin:18px 0 7px}
        input{width:100%;padding:12px;border-radius:9px;border:1px solid #394762;
              background:#0b1020;color:#f5f7fb}
        .actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}
        .btn{display:inline-block;padding:11px 14px;border-radius:9px;border:1px solid #394762;
             background:#151c2f;color:#fff;text-decoration:none;cursor:pointer}
        .danger{border-color:#a54251;background:#381720}
        .flash{padding:10px 12px;border:1px solid #7b3540;border-radius:9px;margin:12px 0}
        ul{line-height:1.6}
    </style>
</head>
<body>
<div class="panel">
    <h1>Delete customer account</h1>

    <div class="warning">
        <strong>This is permanent.</strong> PostGuard will delete the customer's
        account and PostGuard records owned by that account. This action cannot
        be undone from the Admin dashboard.
    </div>

    <p class="muted">
        Customer: <strong>{{ user["email"] }}</strong>
    </p>

    <ul>
        <li>{{ counts["principals"] }} principal/profile record(s)</li>
        <li>{{ counts["checks"] }} scan record(s)</li>
        <li>{{ counts["alerts"] }} alert record(s)</li>
        <li>{{ counts["cases"] }} case record(s)</li>
    </ul>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="flash">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <label for="confirm_email">
            Type the customer's email exactly to confirm
        </label>
        <input id="confirm_email" name="confirm_email" type="email"
               autocomplete="off" required>

        <label for="admin_password">
            Enter your current Admin password
        </label>
        <input id="admin_password" name="admin_password" type="password"
               autocomplete="current-password" required>

        <div class="actions">
            <button class="btn danger" type="submit">
                Permanently delete customer
            </button>
            <a class="btn" href="{{ url_for('admin_users') }}">Cancel</a>
        </div>
    </form>
</div>
</body>
</html>
"""


@app.route("/admin/users/<int:user_id>/delete", methods=["GET", "POST"])
@admin_required
@limiter.limit("5 per minute", methods=["POST"])
def admin_delete_user(user_id):
    if user_id == session.get("uid"):
        abort(400)

    c = db()

    user = c.execute(
        """
        SELECT id, email, role
        FROM users
        WHERE id=?
        """,
        (user_id,),
    ).fetchone()

    if not user:
        c.close()
        abort(404)

    # Admin accounts are never removable through the customer deletion flow.
    if (user["role"] or "user") == "admin":
        c.close()
        abort(403)

    counts = {
        "principals": c.execute(
            "SELECT COUNT(*) AS n FROM principals WHERE user_id=?",
            (user_id,),
        ).fetchone()["n"],
        "checks": c.execute(
            "SELECT COUNT(*) AS n FROM checks WHERE user_id=?",
            (user_id,),
        ).fetchone()["n"],
        "alerts": c.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE user_id=?",
            (user_id,),
        ).fetchone()["n"],
        "cases": c.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE user_id=?",
            (user_id,),
        ).fetchone()["n"],
    }

    if request.method == "POST":
        confirm_email = request.form.get("confirm_email", "").strip().lower()
        admin_password = request.form.get("admin_password", "")

        if confirm_email != user["email"].strip().lower():
            c.close()
            flash("The customer email confirmation did not match.")
            return render_template_string(
                ADMIN_DELETE_USER_PAGE,
                user=user,
                counts=counts,
            ), 400

        admin = c.execute(
            """
            SELECT id, password, role
            FROM users
            WHERE id=?
            """,
            (session["uid"],),
        ).fetchone()

        if (
            not admin
            or (admin["role"] or "user") != "admin"
            or not check_password_hash(admin["password"], admin_password)
        ):
            c.close()
            flash("Admin password verification failed.")
            return render_template_string(
                ADMIN_DELETE_USER_PAGE,
                user=user,
                counts=counts,
            ), 403

        # Delete child/customer-owned data first, then the account itself.
        # No plaintext password or customer email is written to the audit log.
        c.execute("DELETE FROM alerts WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM cases WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM checks WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM principals WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM audit WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        c.commit()
        c.close()

        audit("admin_delete_customer", f"deleted_user_id={user_id}")
        flash("Customer account and PostGuard-owned customer records were deleted.")
        return redirect(url_for("admin_users"))

    c.close()

    return render_template_string(
        ADMIN_DELETE_USER_PAGE,
        user=user,
        counts=counts,
    )


@app.post("/admin/users/<int:user_id>/force-password-reset")
@admin_required
def admin_force_password_reset(user_id):
    if user_id == session.get("uid"):
        abort(400)

    c = db()
    user = c.execute(
        "SELECT id, role FROM users WHERE id=?",
        (user_id,),
    ).fetchone()

    if not user:
        c.close()
        abort(404)

    if user["role"] == "admin":
        c.close()
        abort(403)

    c.execute(
        """
        UPDATE users
        SET reset_required=1
        WHERE id=?
        """,
        (user_id,),
    )
    c.commit()
    c.close()

    audit("admin_force_password_reset", f"user_id={user_id}")
    flash("Password reset required at the customer's next sign-in.")
    return redirect(url_for("admin_users"))


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
    c=db(); user=c.execute("SELECT id,email,role,enabled,reset_required,created_at FROM users WHERE id=?",(user_id,)).fetchone()
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
        version="6.2",
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
