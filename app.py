import os
import re
import json
import io
import secrets
import hmac
import sqlite3
import base64
import hashlib
import logging
import smtplib
import ssl
import struct
import time
from email.message import EmailMessage
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

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
import qrcode


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

POSTGUARD_ENV = os.getenv("POSTGUARD_ENV", "development").strip().lower()
IS_PRODUCTION = POSTGUARD_ENV == "production" or os.getenv("RENDER", "").strip().lower() == "true"

configured_secret = os.getenv("POSTGUARD_SECRET", "").strip()
if IS_PRODUCTION and len(configured_secret) < 32:
    raise RuntimeError(
        "POSTGUARD_SECRET must be configured with at least 32 characters in production."
    )

app.secret_key = configured_secret or secrets.token_hex(32)

app.config.update(
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
    PREFERRED_URL_SCHEME="https" if IS_PRODUCTION else "http",
)

# Production logging intentionally avoids passwords, tokens, captions and image content.
logging.basicConfig(
    level=os.getenv("POSTGUARD_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "media-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self' https://checkout.stripe.com; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    )
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    if request.endpoint not in ("health", "ready"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
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

    def rollback(self):
        self.connection.rollback()

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

        CREATE TABLE IF NOT EXISTS auth_tokens(
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            kind TEXT,
            token_hash TEXT UNIQUE,
            expires_at TEXT,
            used_at TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS security_events(
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            event_type TEXT,
            success INTEGER,
            ip_hash TEXT,
            user_agent TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS paid_checkouts(
            checkout_session_id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            plan TEXT NOT NULL,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            payment_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            consumed_at TEXT,
            user_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS demo_trials(
            email TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            user_id INTEGER
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
    ensure_column("users", "email_verified", "INTEGER DEFAULT 0")
    ensure_column("users", "mfa_secret", "TEXT")
    ensure_column("users", "mfa_enabled", "INTEGER DEFAULT 0")
    ensure_column("users", "last_login_at", "TEXT")
    ensure_column("users", "subscription_plan", "TEXT")
    ensure_column("users", "subscription_status", "TEXT")
    ensure_column("users", "stripe_customer_id", "TEXT")
    ensure_column("users", "stripe_subscription_id", "TEXT")
    ensure_column("users", "stripe_checkout_session_id", "TEXT")
    ensure_column("users", "trial_ends_at", "TEXT")
    c.execute("UPDATE users SET enabled=1 WHERE enabled IS NULL")
    c.execute("UPDATE users SET reset_required=0 WHERE reset_required IS NULL")
    c.execute("UPDATE users SET email_verified=0 WHERE email_verified IS NULL")
    c.execute("UPDATE users SET mfa_enabled=0 WHERE mfa_enabled IS NULL")

    # Existing administrator accounts are trusted as verified during migration.
    c.execute("UPDATE users SET email_verified=1 WHERE role='admin'")

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
# PRODUCTION SECURITY HELPERS
# ============================================================

def _iso_to_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _request_ip_hash():
    raw = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    raw = raw.split(",", 1)[0].strip()
    key = app.secret_key.encode("utf-8")
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def security_event(event_type, success, user_id=None):
    try:
        c = db()
        # Enforce the published 12-month security/audit-event retention window.
        cutoff = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        c.execute("DELETE FROM security_events WHERE created_at < ?", (cutoff,))
        c.execute(
            """
            INSERT INTO security_events(
                user_id,event_type,success,ip_hash,user_agent,created_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                user_id,
                event_type[:80],
                1 if success else 0,
                _request_ip_hash(),
                (request.headers.get("User-Agent") or "")[:240],
                now(),
            ),
        )
        c.commit()
        c.close()
    except Exception:
        app.logger.exception("Unable to record security event")


def _smtp_configured():
    """Compatibility name: transactional email now uses the Resend HTTPS API."""
    api_key = (
        os.getenv("POSTGUARD_RESEND_API_KEY", "").strip()
        or os.getenv("POSTGUARD_SMTP_PASSWORD", "").strip()
    )
    return bool(api_key and os.getenv("POSTGUARD_EMAIL_FROM", "").strip())


def send_email(to_address, subject, text_body, cc_addresses=None):
    """Send transactional email through Resend's HTTPS API.

    POSTGUARD_RESEND_API_KEY is preferred. For a zero-downtime migration from the
    earlier SMTP configuration, POSTGUARD_SMTP_PASSWORD is accepted as a fallback
    because it already contains the Resend API key.
    """
    api_key = (
        os.getenv("POSTGUARD_RESEND_API_KEY", "").strip()
        or os.getenv("POSTGUARD_SMTP_PASSWORD", "").strip()
    )
    sender = os.getenv("POSTGUARD_EMAIL_FROM", "").strip()

    if not api_key or not sender:
        app.logger.warning("Transactional email not configured; subject=%s", subject)
        return False

    message_payload = {
        "from": sender,
        "to": [to_address],
        "subject": subject,
        "text": text_body,
    }
    cleaned_cc = [x.strip() for x in (cc_addresses or []) if x and x.strip()]
    if cleaned_cc:
        message_payload["cc"] = cleaned_cc

    payload = json.dumps(message_payload).encode("utf-8")

    req = Request(
        "https://api.resend.com/emails",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "PostGuard/7.7.5",
        },
    )

    try:
        with urlopen(req, timeout=15) as response:
            status = getattr(response, "status", response.getcode())
            if 200 <= status < 300:
                return True
            app.logger.error("Resend API returned HTTP %s", status)
            return False
    except HTTPError as exc:
        # Resend error bodies can help diagnose domain/permission issues, but never
        # log request headers or the API key.
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
        except Exception:
            detail = ""
        app.logger.error("Resend API HTTP error %s: %s", exc.code, detail)
        return False
    except URLError as exc:
        app.logger.error("Resend API connection error: %s", exc.reason)
        return False
    except Exception:
        app.logger.exception("Unexpected Resend API email failure")
        return False


def create_auth_token(user_id, kind, minutes=30):
    raw = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    c = db()
    c.execute(
        """
        INSERT INTO auth_tokens(user_id,kind,token_hash,expires_at,used_at,created_at)
        VALUES(?,?,?,?,?,?)
        """,
        (user_id, kind, _hash_token(raw), expires.isoformat(), None, now()),
    )
    c.commit()
    c.close()
    return raw


def consume_auth_token(raw, kind):
    if not raw:
        return None
    c = db()
    row = c.execute(
        """
        SELECT * FROM auth_tokens
        WHERE token_hash=? AND kind=? AND used_at IS NULL
        ORDER BY id DESC LIMIT 1
        """,
        (_hash_token(raw), kind),
    ).fetchone()
    if not row:
        c.close()
        return None
    expires = _iso_to_dt(row["expires_at"])
    if not expires or expires < datetime.now(timezone.utc):
        c.close()
        return None
    c.execute("UPDATE auth_tokens SET used_at=? WHERE id=?", (now(), row["id"]))
    c.commit()
    c.close()
    return row


def public_base_url():
    configured = os.getenv("POSTGUARD_PUBLIC_URL", "").strip().rstrip("/")
    if configured:
        return configured
    return request.url_root.rstrip("/")


def send_verification_email(user_id, email):
    raw = create_auth_token(user_id, "verify_email", minutes=60)
    link = f"{public_base_url()}/verify-email/{quote(raw)}"
    return send_email(
        email,
        "Verify your PostGuard email",
        "Verify your PostGuard email address by opening this link:\n\n"
        f"{link}\n\nThis link expires in 60 minutes. "
        "If you did not create a PostGuard account, ignore this email.",
    )


def send_password_reset_email(user_id, email):
    raw = create_auth_token(user_id, "password_reset", minutes=30)
    link = f"{public_base_url()}/forgot-password/{quote(raw)}"
    return send_email(
        email,
        "Reset your PostGuard password",
        "A password reset was requested for your PostGuard account.\n\n"
        f"Open this link to choose a new password:\n{link}\n\n"
        "This link expires in 30 minutes and can be used once. "
        "If you did not request this, ignore this email.",
    )


def _totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_code(secret, for_time=None):
    for_time = int(for_time or time.time())
    counter = for_time // 30
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1000000:06d}"


def verify_totp(secret, code):
    code = re.sub(r"\D", "", code or "")
    if len(code) != 6:
        return False
    current = int(time.time())
    return any(
        hmac.compare_digest(_totp_code(secret, current + offset), code)
        for offset in (-30, 0, 30)
    )


def admin_mfa_required():
    return os.getenv("POSTGUARD_REQUIRE_ADMIN_MFA", "1" if IS_PRODUCTION else "0") == "1"


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
            "SELECT role, enabled, reset_required, email_verified, subscription_status, trial_ends_at FROM users WHERE id=?",
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

        if account["role"] != "admin" and account["subscription_status"] == "trialing" and account["trial_ends_at"]:
            try:
                trial_end = datetime.fromisoformat(account["trial_ends_at"])
                if trial_end.tzinfo is None:
                    trial_end = trial_end.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) >= trial_end:
                    c2 = db()
                    c2.execute("UPDATE users SET subscription_status='trial_expired' WHERE id=?", (session["uid"],))
                    c2.commit()
                    c2.close()
                    session.clear()
                    flash("Your 7-day PostGuard demo has ended. Choose a plan to continue using the service.")
                    return redirect(url_for("join_postguard"))
            except (TypeError, ValueError):
                session.clear()
                flash("Your demo status could not be verified. Please sign in again or contact PostGuard.")
                return redirect(url_for("login"))

        session["role"] = account["role"] or "user"

        if (
            account["role"] == "admin"
            and admin_mfa_required()
            and session.get("mfa_pending")
            and request.endpoint not in ("mfa_setup", "mfa_challenge", "logout")
        ):
            return redirect(url_for("mfa_challenge"))

        if (
            account["role"] != "admin"
            and account["email_verified"] == 0
            and request.endpoint not in ("verify_email_notice", "resend_verification", "logout")
        ):
            return redirect(url_for("verify_email_notice"))

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



# ============================================================
# PAID SIGN-UP / STRIPE CHECKOUT
# Registration is intentionally fail-closed: a verified paid Stripe Checkout
# session is required before a customer account can be created.
# ============================================================

PLANS = {
    "personal": {
        "name": "PostGuard Personal",
        "price": "£49",
        "price_env": "POSTGUARD_STRIPE_PRICE_PERSONAL",
        "strap": "Pre-post protection for your everyday social media activity.",
        "features": [
            "Unlimited pre-post scanning for every post you submit to PostGuard before publishing",
            "Privacy and personal-security risk analysis for each submitted post",
            "Clear advice and recommendations before you decide whether to publish",
            "Safer-post creation, re-scan, scan history and alerts",
        ],
    },
    "executive": {
        "name": "PostGuard Executive",
        "price": "£199",
        "price_env": "POSTGUARD_STRIPE_PRICE_EXECUTIVE",
        "strap": "Enhanced protection package.",
        "features": [
            "Features to be confirmed",
        ],
    },
    "vip": {
        "name": "PostGuard VIP",
        "price": "£300",
        "price_env": "POSTGUARD_STRIPE_PRICE_VIP",
        "strap": "Premium protection package.",
        "features": [
            "Features to be confirmed",
        ],
    },
}


def stripe_configured():
    if not os.getenv("POSTGUARD_STRIPE_SECRET_KEY", "").strip():
        return False
    return all(os.getenv(plan["price_env"], "").strip() for plan in PLANS.values())


def free_access_promo_configured():
    # Keep the actual promo code out of source control. Configure it privately
    # in Render as POSTGUARD_FREE_ACCESS_CODE. A minimum length makes accidental
    # weak values less likely.
    return len(os.getenv("POSTGUARD_FREE_ACCESS_CODE", "").strip()) >= 12


def free_access_promo_valid(candidate):
    configured = os.getenv("POSTGUARD_FREE_ACCESS_CODE", "").strip()
    candidate = (candidate or "").strip()
    if len(configured) < 12 or not candidate:
        return False
    return hmac.compare_digest(candidate, configured)


def stripe_api(method, path, form_data=None):
    secret = os.getenv("POSTGUARD_STRIPE_SECRET_KEY", "").strip()
    if not secret:
        raise RuntimeError("Stripe is not configured")

    data = None
    if form_data is not None:
        data = urlencode(form_data).encode("utf-8")

    req = Request(
        "https://api.stripe.com" + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PostGuard/7.7",
        },
    )
    try:
        with urlopen(req, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:1200]
        except Exception:
            detail = ""
        app.logger.error("Stripe API HTTP error %s: %s", exc.code, detail)
        raise


def create_checkout_session(plan_key):
    plan = PLANS[plan_key]
    public_url = os.getenv("POSTGUARD_PUBLIC_URL", "").strip().rstrip("/")
    price_id = os.getenv(plan["price_env"], "").strip()
    if not public_url.startswith("https://") or not price_id:
        raise RuntimeError("PostGuard payment configuration is incomplete")

    return stripe_api("POST", "/v1/checkout/sessions", {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": public_url + "/payment/success?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": public_url + "/join?cancelled=1",
        "billing_address_collection": "auto",
        "allow_promotion_codes": "true",
        "payment_method_collection": "always",
        "metadata[postguard_plan]": plan_key,
        "subscription_data[trial_period_days]": "7",
        "subscription_data[metadata][postguard_plan]": plan_key,
    })


PAID_SPLASH_PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join PostGuard · Choose your protection</title>
<style>
:root{color-scheme:dark;--bg:#07101d;--card:#0f1c2e;--line:#263c5c;--text:#f7f9fd;--muted:#9badc6;--blue:#8db3ff;--green:#8de6b7}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 15% 10%,rgba(66,113,205,.18),transparent 28%),#07101d;color:var(--text);font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{min-height:100vh;max-width:1220px;margin:auto;padding:44px 24px 64px}.top{display:flex;align-items:center;justify-content:space-between;gap:24px}.brand{display:flex;align-items:center;gap:14px;font-weight:900;letter-spacing:.04em}.brand img{width:62px;height:62px;object-fit:cover;border-radius:50%;border:1px solid #355987}.login{color:#dce7fb;text-decoration:none;border:1px solid #345071;padding:10px 16px;border-radius:10px}.hero{text-align:center;max-width:780px;margin:54px auto 38px}.hero img{width:160px;height:160px;object-fit:cover;border-radius:50%;border:1px solid #355987;box-shadow:0 20px 60px rgba(0,0,0,.35)}.eyebrow{margin-top:20px;color:var(--blue);font-size:.78rem;font-weight:850;text-transform:uppercase;letter-spacing:.16em}h1{font-size:clamp(2.4rem,5vw,4.6rem);line-height:1;margin:13px 0 18px;letter-spacing:-.05em}.hero p{color:#b7c5d8;line-height:1.7;font-size:1.05rem}.notice{max-width:760px;margin:0 auto 28px;padding:13px 16px;border:1px solid #40536e;background:#101b2b;border-radius:12px;color:#c9d5e6;text-align:center}.cancel{border-color:#70444b;background:#281a20;color:#ffd7da}.demo{max-width:760px;margin:0 auto 30px;background:linear-gradient(135deg,#132a24,#0d1d1a);border:1px solid #2f745a;border-radius:20px;padding:24px;text-align:center;box-shadow:0 18px 50px rgba(0,0,0,.18)}.demo h2{margin:0 0 8px}.demo p{color:#b9d9cb;line-height:1.55}.demo .free{font-size:2rem;font-weight:900;margin:8px 0}.demo .buy{max-width:360px}.plans{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.plan{position:relative;background:linear-gradient(180deg,#122137,#0c1727);border:1px solid var(--line);border-radius:20px;padding:26px;box-shadow:0 18px 50px rgba(0,0,0,.2)}.plan.featured{border-color:#6a91d3;transform:translateY(-6px)}.tag{position:absolute;top:16px;right:16px;background:#1d3b67;color:#cfe0ff;padding:6px 9px;border-radius:999px;font-size:.7rem;font-weight:800}.plan h2{margin:0 0 8px;font-size:1.35rem}.strap{color:var(--muted);min-height:44px;font-size:.9rem;line-height:1.5}.price{font-size:2.45rem;font-weight:900;margin:18px 0 2px;letter-spacing:-.04em}.per{color:var(--muted);font-size:.85rem}.features{list-style:none;padding:0;margin:22px 0}.features li{padding:8px 0;color:#c9d5e5;font-size:.88rem}.features li:before{content:"✓";color:var(--green);font-weight:900;margin-right:9px}.buy{width:100%;border:0;border-radius:11px;padding:13px 15px;font-weight:900;background:linear-gradient(135deg,#eef4ff,#b9d0fb);color:#07101d;cursor:pointer}.buy:disabled{opacity:.5;cursor:not-allowed}.small{margin:26px auto 0;max-width:830px;text-align:center;color:#778ba6;font-size:.78rem;line-height:1.6}.small a{color:#a9c8ff}.promo{max-width:760px;margin:30px auto 0;padding:22px;border:1px solid #40536e;background:#0d1929;border-radius:18px;text-align:center}.promo h2{margin:0 0 8px}.promo p{color:#aebed3;line-height:1.55}.promo form{display:flex;gap:10px;max-width:560px;margin:16px auto 0}.promo input{flex:1;min-width:0;border:1px solid #355071;background:#081220;color:#f7f9fd;border-radius:10px;padding:13px 14px}.promo button{border:0;border-radius:10px;padding:13px 18px;font-weight:900;background:#dce8ff;color:#07101d;cursor:pointer}.promo .muted{font-size:.8rem;color:#7f92ad}@media(max-width:620px){.promo form{flex-direction:column}}.flash{max-width:760px;margin:0 auto 20px;border:1px solid #6b464d;background:#2a1b21;color:#ffd9dc;border-radius:12px;padding:12px 14px;text-align:center}@media(max-width:900px){.plans{grid-template-columns:1fr}.plan.featured{transform:none}.top{align-items:flex-start}.hero{margin-top:38px}}
</style>
</head>
<body><div class="wrap">
<div class="top"><div class="brand"><img src="{{ url_for('static', filename='postguard_logo.jpg') }}" alt="PostGuard logo"><span>POSTGUARD</span></div><a class="login" href="{{ url_for('login') }}">Existing user sign in</a></div>
<div class="hero"><img src="{{ url_for('static', filename='postguard_logo.jpg') }}" alt="PostGuard"><div class="eyebrow">Protect what you post</div><h1>Choose your level of protection.</h1><p>Choose a plan and start with a 7-day free trial. A payment method is required. Unless you cancel before the trial ends, your selected monthly subscription starts automatically and continues each month until cancelled.</p></div>
{% with messages = get_flashed_messages() %}{% if messages %}<div class="flash">{{ messages[-1] }}</div>{% endif %}{% endwith %}
{% if request.args.get('cancelled') %}<div class="notice cancel">Payment was cancelled. No PostGuard account has been created.</div>{% endif %}
{% if not payments_ready %}<div class="notice">Secure subscription signup is currently being configured.</div>{% endif %}
<div class="notice"><strong>7 days free on every plan.</strong> Payment method required. Cancel before your 7-day trial ends to avoid being charged. If you do not cancel, your selected plan renews automatically every month until cancelled.</div>
<div class="plans">
{% for key, plan in plans.items() %}
<div class="plan {% if key == 'executive' %}featured{% endif %}">{% if key == 'executive' %}<div class="tag">POPULAR</div>{% endif %}<h2>{{ plan.name }}</h2><div class="strap">{{ plan.strap }}</div><div class="price">7 days free</div><div class="per">then {{ plan.price }}/month · recurring subscription</div><ul class="features">{% for item in plan.features %}<li>{{ item }}</li>{% endfor %}</ul><form method="post" action="{{ url_for('start_checkout', plan_key=key) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="buy" {% if not payments_ready %}disabled{% endif %}>Start 7-day free trial</button></form></div>
{% endfor %}
</div>
{% if promo_ready %}
<div class="promo">
<h2>Free-access promo code</h2>
<p>If PostGuard has issued you a complimentary-access code, enter it below. A valid code unlocks registration without Stripe or a payment card.</p>
<form method="post" action="{{ url_for('redeem_free_access_promo') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<input type="password" name="promo_code" autocomplete="off" required placeholder="Enter promo code" aria-label="Free-access promo code">
<button type="submit">Apply code</button>
</form>
<div class="muted">Promo access is complimentary and does not automatically create a paid recurring subscription.</div>
</div>
{% endif %}
<div class="small">PostGuard provides security and privacy decision support. The final decision to publish content remains with the user. A payment method is required for the 7-day free trial. Unless cancelled before the trial ends, the selected plan is charged at the displayed monthly price and renews automatically each month until cancelled. See the <a href="{{ url_for('terms_page') }}">Terms</a> and <a href="{{ url_for('privacy_page') }}">Privacy Notice</a>.</div>
</div></body></html>
"""


@app.get("/join")
def join_postguard():
    if "uid" in session:
        return redirect(url_for("home"))
    return render_template_string(PAID_SPLASH_PAGE, plans=PLANS, payments_ready=stripe_configured(), promo_ready=free_access_promo_configured())


@app.post("/demo/start")
@limiter.limit("5 per minute")
def start_demo():
    if "uid" in session:
        return redirect(url_for("home"))
    session.pop("paid_checkout_session_id", None)
    session.pop("paid_checkout_email", None)
    session.pop("paid_plan", None)
    session.pop("paid_checkout_at", None)
    session["demo_registration"] = True
    session["demo_registration_at"] = int(time.time())
    return redirect(url_for("register"))


@app.post("/promo/redeem")
@limiter.limit("5 per minute")
def redeem_free_access_promo():
    if "uid" in session:
        return redirect(url_for("home"))

    # Use one generic failure message so the endpoint does not reveal whether
    # promo access is configured. Never log the submitted code.
    if not free_access_promo_valid(request.form.get("promo_code", "")):
        flash("That promo code could not be accepted.")
        return redirect(url_for("join_postguard"))

    # Promo registration is deliberately separate from Stripe and demo state.
    for key in (
        "paid_checkout_session_id", "paid_checkout_email", "paid_plan",
        "paid_trial_ends_at", "paid_subscription_status", "paid_checkout_at",
        "demo_registration", "demo_registration_at"
    ):
        session.pop(key, None)
    session["promo_registration"] = True
    session["promo_registration_at"] = int(time.time())
    flash("Promo code accepted. Create your PostGuard account to activate complimentary access.")
    return redirect(url_for("register"))


@app.post("/subscribe/<plan_key>")
@limiter.limit("10 per minute")
def start_checkout(plan_key):
    if plan_key not in PLANS:
        abort(404)
    if "uid" in session:
        return redirect(url_for("home"))
    if not stripe_configured():
        flash("Secure payment processing is not configured yet.")
        return redirect(url_for("join_postguard"))
    try:
        checkout = create_checkout_session(plan_key)
        checkout_url = checkout.get("url")
        if not checkout_url:
            raise RuntimeError("Stripe did not return a checkout URL")
        return redirect(checkout_url)
    except Exception:
        app.logger.exception("Unable to create Stripe Checkout session")
        flash("We could not start secure checkout. Please try again shortly.")
        return redirect(url_for("join_postguard"))


@app.get("/payment/success")
@limiter.limit("20 per minute")
def payment_success():
    checkout_session_id = request.args.get("session_id", "").strip()
    if not checkout_session_id.startswith("cs_"):
        flash("Payment confirmation could not be verified.")
        return redirect(url_for("join_postguard"))
    try:
        checkout = stripe_api("GET", "/v1/checkout/sessions/" + quote(checkout_session_id, safe=""))
    except Exception:
        flash("We could not verify your payment. Please contact PostGuard if you were charged.")
        return redirect(url_for("join_postguard"))

    plan_key = ((checkout.get("metadata") or {}).get("postguard_plan") or "").strip()
    email = (((checkout.get("customer_details") or {}).get("email")) or checkout.get("customer_email") or "").strip().lower()
    payment_status = (checkout.get("payment_status") or "").strip().lower()
    status = (checkout.get("status") or "").strip().lower()
    mode = (checkout.get("mode") or "").strip().lower()
    subscription_id = (checkout.get("subscription") or "").strip()
    trial_ends_at = None
    stripe_subscription_status = "trialing"
    if subscription_id.startswith("sub_"):
        try:
            subscription = stripe_api("GET", "/v1/subscriptions/" + quote(subscription_id, safe=""))
            stripe_subscription_status = (subscription.get("status") or "trialing").strip().lower()
            trial_end_epoch = subscription.get("trial_end")
            if trial_end_epoch:
                trial_ends_at = datetime.fromtimestamp(int(trial_end_epoch), tz=timezone.utc).isoformat()
        except Exception:
            app.logger.exception("Unable to retrieve Stripe subscription trial details")

    if plan_key not in PLANS or not email or status != "complete" or mode != "subscription" or payment_status not in ("paid", "no_payment_required"):
        flash("Your subscription has not been confirmed as paid yet. Registration remains locked.")
        return redirect(url_for("join_postguard"))

    c = db()

    # A customer who started with the free demo can purchase later using the
    # same email. Upgrade that existing account instead of trying to create a
    # duplicate registration.
    existing_user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if existing_user and (existing_user["role"] or "user") != "admin":
        try:
            existing_checkout = c.execute("SELECT * FROM paid_checkouts WHERE checkout_session_id=?", (checkout_session_id,)).fetchone()
            if not existing_checkout:
                c.execute(
                    """INSERT INTO paid_checkouts(checkout_session_id,email,plan,stripe_customer_id,stripe_subscription_id,payment_status,created_at,consumed_at,user_id) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (checkout_session_id, email, plan_key, checkout.get("customer"), checkout.get("subscription"), payment_status, now(), now(), existing_user["id"]),
                )
            elif existing_checkout["consumed_at"]:
                c.close()
                flash("This checkout has already been applied to your PostGuard account.")
                return redirect(url_for("login"))
            else:
                c.execute("UPDATE paid_checkouts SET consumed_at=?, user_id=? WHERE checkout_session_id=?", (now(), existing_user["id"], checkout_session_id))

            c.execute(
                """UPDATE users SET subscription_plan=?, subscription_status=?, stripe_customer_id=?, stripe_subscription_id=?, stripe_checkout_session_id=?, trial_ends_at=? WHERE id=?""",
                (plan_key, stripe_subscription_status, checkout.get("customer"), checkout.get("subscription"), checkout_session_id, trial_ends_at, existing_user["id"]),
            )
            c.commit()
            c.close()
            flash("Your 7-day trial is active. Sign in to continue. Cancel before the trial ends to avoid the first monthly charge.")
            return redirect(url_for("login"))
        except (psycopg.errors.UniqueViolation, sqlite3.IntegrityError):
            c.rollback()
            c.close()
            flash("Your payment was received, but the account upgrade needs review. Please contact PostGuard.")
            return redirect(url_for("login"))

    existing = c.execute("SELECT * FROM paid_checkouts WHERE checkout_session_id=?", (checkout_session_id,)).fetchone()
    if existing and existing["consumed_at"]:
        c.close()
        flash("This paid checkout has already been used to create an account.")
        return redirect(url_for("login"))
    if not existing:
        try:
            c.execute(
                """INSERT INTO paid_checkouts(checkout_session_id,email,plan,stripe_customer_id,stripe_subscription_id,payment_status,created_at) VALUES(?,?,?,?,?,?,?)""",
                (checkout_session_id, email, plan_key, checkout.get("customer"), checkout.get("subscription"), payment_status, now()),
            )
            c.commit()
        except (psycopg.errors.UniqueViolation, sqlite3.IntegrityError):
            c.rollback()
    c.close()

    session["paid_checkout_session_id"] = checkout_session_id
    session["paid_checkout_email"] = email
    session["paid_plan"] = plan_key
    session["paid_trial_ends_at"] = trial_ends_at
    session["paid_subscription_status"] = stripe_subscription_status
    session["paid_checkout_at"] = int(time.time())
    return redirect(url_for("register"))


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
                    <span>Get clear LOW RISK or DO NOT POST guidance.</span>
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
                    {% if demo_mode %}<p style="margin-top:9px;color:#7fe0ae;font-weight:800">7-Day Free Demo · no payment required</p>{% elif paid_plan %}<p style="margin-top:9px;color:#7fe0ae;font-weight:800">{{ paid_plan.name }} · 7 days free, then {{ paid_plan.price }}/month unless cancelled</p>{% endif %}
                {% else %}
                    <h2>Welcome back</h2>
                    <p>Sign in to your PostGuard intelligence centre.</p>
                {% endif %}
            </div>

            <nav class="switch" aria-label="Account access">
                <a href="{{ url_for('login') }}" class="{% if mode == 'login' %}active{% endif %}">Returning user</a>
                <a href="{{ url_for('join_postguard') }}" class="{% if mode == 'register' %}active{% endif %}">New user</a>
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
                           value="{{ paid_email|default('') }}" placeholder="you@example.com" {% if mode == 'register' and paid_plan %}readonly{% endif %} required>
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
                    Passwords are stored as secure hashes rather than readable passwords.<br>
                    By creating an account you confirm you are at least 16 and agree to the
                    <a class="mini-link" href="{{ url_for('terms_page') }}">Terms of Service</a> and acknowledge the
                    <a class="mini-link" href="{{ url_for('privacy_page') }}">Privacy Notice</a>.
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
                    <a class="mini-link" href="{{ url_for('join_postguard') }}">Create an account</a>.
                    Administrators use this same secure sign-in.
                    <br><a class="mini-link" href="{{ url_for('forgot_password') }}">Forgot your password?</a>
                    · <a class="mini-link" href="{{ url_for('privacy_page') }}">Privacy</a>
                    · <a class="mini-link" href="{{ url_for('terms_page') }}">Terms</a>
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





@app.after_request
def add_postguard_sidebar_logo(response):
    """Place the PostGuard logo beneath left-side navigation on legacy HTML pages."""
    try:
        if (
            response.status_code == 200
            and response.mimetype == "text/html"
            and not response.direct_passthrough
        ):
            html = response.get_data(as_text=True)

            if (
                "<body" in html.lower()
                and "sidebar-logo-injected" not in html
                and "AUTH_ENTRY_PAGE" not in html
            ):
                css = """<style>
.sidebar-logo-injected{display:flex;justify-content:center;padding:18px 10px 8px;margin-top:18px}
.sidebar-logo-injected img{width:110px;height:110px;border-radius:50%;object-fit:cover;border:1px solid rgba(135,173,255,.34);box-shadow:0 14px 38px rgba(0,0,0,.30)}
@media(max-width:800px){.sidebar-logo-injected img{width:88px;height:88px}}
</style>"""

                logo = """<div class="sidebar-logo-injected"><img src="/static/postguard_logo.jpg" alt="PostGuard"></div>"""

                if "</head>" in html:
                    html = html.replace("</head>", css + "</head>", 1)

                # Prefer left nav/sidebar containers and place logo after their options.
                nav_match = re.search(r"(<nav[^>]*>.*?</nav>)", html, flags=re.I|re.S)
                if nav_match:
                    nav_html = nav_match.group(1)
                    nav_html = nav_html.replace("</nav>", logo + "</nav>", 1)
                    html = html[:nav_match.start()] + nav_html + html[nav_match.end():]
                    response.set_data(html)
    except Exception:
        # Branding should never stop a valid application response.
        pass
    return response

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if "uid" in session:
        return redirect(url_for("home"))

    paid_checkout_session_id = session.get("paid_checkout_session_id", "")
    paid_checkout_email = session.get("paid_checkout_email", "")
    paid_plan = session.get("paid_plan", "")
    paid_checkout_at = int(session.get("paid_checkout_at", 0) or 0)
    demo_mode = bool(session.get("demo_registration"))
    demo_registration_at = int(session.get("demo_registration_at", 0) or 0)
    promo_mode = bool(session.get("promo_registration"))
    promo_registration_at = int(session.get("promo_registration_at", 0) or 0)

    paid_mode = bool(
        paid_checkout_session_id and paid_checkout_email and paid_plan in PLANS
        and paid_checkout_at and time.time() - paid_checkout_at <= 3600
    )
    demo_mode = bool(demo_mode and demo_registration_at and time.time() - demo_registration_at <= 3600)
    promo_mode = bool(promo_mode and promo_registration_at and time.time() - promo_registration_at <= 3600)

    if not paid_mode and not demo_mode and not promo_mode:
        session.pop("paid_checkout_session_id", None)
        session.pop("paid_checkout_email", None)
        session.pop("paid_plan", None)
        session.pop("paid_trial_ends_at", None)
        session.pop("paid_subscription_status", None)
        session.pop("paid_checkout_at", None)
        session.pop("demo_registration", None)
        session.pop("demo_registration_at", None)
        session.pop("promo_registration", None)
        session.pop("promo_registration_at", None)
        flash("Choose a paid plan or use an authorised PostGuard access offer before registering.")
        return redirect(url_for("join_postguard"))

    paid_row = None
    if paid_mode:
        c_paid = db()
        paid_row = c_paid.execute(
            "SELECT * FROM paid_checkouts WHERE checkout_session_id=?",
            (paid_checkout_session_id,),
        ).fetchone()
        c_paid.close()
        if (not paid_row or paid_row["consumed_at"] or paid_row["email"].strip().lower() != paid_checkout_email.strip().lower()
                or paid_row["plan"] != paid_plan or paid_row["payment_status"] not in ("paid", "no_payment_required")):
            flash("A valid unused paid checkout is required before registration.")
            return redirect(url_for("join_postguard"))

    if request.method == "POST":
        email = (paid_checkout_email if paid_mode else request.form.get("email", "")).strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not email:
            flash("Email address is required.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

        email_pattern = (
            r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
            r"@[A-Za-z0-9-]+"
            r"(?:\.[A-Za-z0-9-]+)+$"
        )

        if not re.match(email_pattern, email):
            flash("Enter a valid email address.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

        if not password:
            flash("Password is required.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

        if password != confirm:
            flash("Passwords do not match.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

        if len(password) < 12:
            flash("Password must be at least 12 characters.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

        c = db()
        existing = c.execute(
            "SELECT id FROM users WHERE email=?",
            (email,),
        ).fetchone()

        if existing:
            c.close()
            flash("An account with that email already exists.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

        if demo_mode:
            previous_demo = c.execute("SELECT email FROM demo_trials WHERE email=?", (email,)).fetchone()
            if previous_demo:
                c.close()
                flash("A 7-day PostGuard demo has already been used with this email address. Choose a paid plan to continue.")
                return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email="", paid_plan=None, demo_mode=True, promo_mode=False)

        try:
            user = c.execute(
                """
                INSERT INTO users(
                    email, password, role, created_at, email_verified,
                    subscription_plan, subscription_status, stripe_customer_id,
                    stripe_subscription_id, stripe_checkout_session_id, trial_ends_at
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                RETURNING id
                """,
                (
                    email,
                    generate_password_hash(password),
                    "user",
                    now(),
                    0,
                    paid_plan if paid_mode else ("promo" if promo_mode else "demo"),
                    paid_subscription_status if paid_mode else ("active" if promo_mode else "trialing"),
                    paid_row["stripe_customer_id"] if paid_mode else None,
                    paid_row["stripe_subscription_id"] if paid_mode else None,
                    paid_checkout_session_id if paid_mode else None,
                    paid_trial_ends_at if paid_mode else (None if promo_mode else (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()),
                ),
            ).fetchone()
        except (psycopg.errors.UniqueViolation, sqlite3.IntegrityError):
            # The pre-check above keeps the normal path friendly, while this
            # database-level catch safely handles two simultaneous registration
            # requests racing for the same unique email address.
            c.rollback()
            c.close()
            flash("An account with that email already exists.")
            return render_template_string(AUTH_ENTRY_PAGE, mode="register", paid_email=paid_checkout_email, paid_plan=PLANS[paid_plan] if paid_mode else None, demo_mode=demo_mode, promo_mode=promo_mode)

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
        if paid_mode:
            c.execute(
                "UPDATE paid_checkouts SET consumed_at=?, user_id=? WHERE checkout_session_id=? AND consumed_at IS NULL",
                (now(), user_id, paid_checkout_session_id),
            )
        elif demo_mode:
            trial_started = datetime.now(timezone.utc)
            trial_expires = trial_started + timedelta(days=7)
            c.execute(
                "INSERT INTO demo_trials(email,started_at,expires_at,consumed_at,user_id) VALUES(?,?,?,?,?)",
                (email, trial_started.isoformat(), trial_expires.isoformat(), now(), user_id),
            )

        c.commit()
        c.close()

        app.logger.info(
            "New PostGuard account registered: user_id=%s",
            user_id,
        )

        plan_name = PLANS[paid_plan]["name"] if paid_mode else ("PostGuard Complimentary Access" if promo_mode else "PostGuard 7-Day Free Demo")
        plan_price = PLANS[paid_plan]["price"] if paid_mode else "£0"
        admin_email = os.getenv("POSTGUARD_ADMIN_EMAIL", "").strip().lower()
        try:
            if paid_mode:
                welcome_detail = f"Your 7-day free trial for {plan_name} is active. A payment method is on file. Unless you cancel before the trial ends, {plan_price}/month will be charged automatically and the subscription will continue monthly until cancelled. You can manage or cancel your subscription from My Account.\n"
            elif promo_mode:
                welcome_detail = "Your complimentary PostGuard access has been activated using an authorised promo code. No payment card is linked and this promo access does not automatically renew into a paid subscription.\n"
            else:
                welcome_detail = "Your 7-day free PostGuard demo has started. No payment has been taken. After 7 days, choose a paid plan to continue using the service.\n"
            send_email(
                email,
                f"Welcome to PostGuard — {plan_name}",
                (
                    f"Welcome to PostGuard.\n\n"
                    + welcome_detail +
                    "Please complete the separate email-verification message before signing in.\n\n"
                    "PostGuard provides security and privacy decision support. The final decision to publish content remains with you.\n\n"
                    "PostGuard\nwww.postguard.uk"
                ),
                cc_addresses=[admin_email] if admin_email and admin_email != email else [],
            )
        except Exception:
            app.logger.exception("Welcome email delivery failed for user_id=%s", user_id)

        try:
            sent = send_verification_email(user_id, email)
        except Exception:
            app.logger.exception("Verification email delivery failed for user_id=%s", user_id)
            sent = False

        if sent:
            flash(
                "Your account has been created. Check your email and verify "
                "your address before signing in."
            )
        else:
            flash(
                "Your account was created, but email delivery is not configured. "
                "Please contact the PostGuard administrator."
            )
        session.pop("paid_checkout_session_id", None)
        session.pop("paid_checkout_email", None)
        session.pop("paid_plan", None)
        session.pop("paid_trial_ends_at", None)
        session.pop("paid_subscription_status", None)
        session.pop("paid_checkout_at", None)
        session.pop("demo_registration", None)
        session.pop("demo_registration_at", None)
        session.pop("promo_registration", None)
        session.pop("promo_registration_at", None)
        return redirect(url_for("login"))

    return render_template_string(
        AUTH_ENTRY_PAGE,
        mode="register",
        paid_email=paid_checkout_email if paid_mode else "",
        paid_plan=PLANS[paid_plan] if paid_mode else None,
        demo_mode=demo_mode,
        promo_mode=promo_mode,
    )


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
            security_event("login_password", True, user["id"])
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

            if role != "admin" and user["subscription_status"] in ("trialing", "trial_expired"):
                expired = user["subscription_status"] == "trial_expired"
                if user["trial_ends_at"] and not expired:
                    try:
                        trial_end = datetime.fromisoformat(user["trial_ends_at"])
                        if trial_end.tzinfo is None:
                            trial_end = trial_end.replace(tzinfo=timezone.utc)
                        expired = datetime.now(timezone.utc) >= trial_end
                    except (TypeError, ValueError):
                        expired = True
                if expired:
                    c.execute("UPDATE users SET subscription_status='trial_expired' WHERE id=?", (user["id"],))
                    c.commit()
                    c.close()
                    flash("Your 7-day PostGuard demo has ended. Choose a plan to continue using the service.")
                    return redirect(url_for("join_postguard"))

            c.close()

            session.clear()
            session.permanent = True

            session["uid"] = user["id"]
            session["email"] = email
            session["role"] = role

            if user["reset_required"] == 1 and role != "admin":
                return redirect(url_for("forced_password_reset"))

            if role != "admin" and user["email_verified"] == 0:
                return redirect(url_for("verify_email_notice"))

            if role == "admin" and admin_mfa_required():
                session["mfa_pending"] = True
                c2 = db()
                mfa_row = c2.execute(
                    "SELECT mfa_enabled FROM users WHERE id=?",
                    (user["id"],),
                ).fetchone()
                c2.close()
                if not mfa_row or mfa_row["mfa_enabled"] != 1:
                    return redirect(url_for("mfa_setup"))
                return redirect(url_for("mfa_challenge"))

            c2 = db()
            c2.execute("UPDATE users SET last_login_at=? WHERE id=?", (now(), user["id"]))
            c2.commit()
            c2.close()
            return redirect(url_for("home"))

        failed_user_id = user["id"] if user else None
        c.close()
        security_event("login_password", False, failed_user_id)

        flash("Invalid credentials.")

    return render_template_string(AUTH_ENTRY_PAGE, mode="login")


@app.post("/logout")
@auth
def logout():
    session.clear()
    return redirect(url_for("login"))



# ============================================================
# EMAIL VERIFICATION / PASSWORD RECOVERY / ADMIN MFA
# ============================================================

SIMPLE_AUTH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · {{ title }}</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
font-family:system-ui,sans-serif;background:#07101d;color:#f6f8fb}
.card{width:min(520px,100%);background:#0d1828;border:1px solid #243754;border-radius:18px;padding:28px}
.logo{display:block;width:96px;height:96px;border-radius:50%;object-fit:cover;margin:0 auto 18px}
h1{margin:0 0 10px}.muted{color:#9aabc2;line-height:1.55}
label{display:block;margin:16px 0 7px}input{width:100%;padding:12px;border-radius:10px;border:1px solid #314662;background:#091524;color:#fff}
.btn{display:inline-block;margin-top:18px;padding:11px 14px;border-radius:10px;border:1px solid #42608d;background:#173054;color:#fff;text-decoration:none;cursor:pointer}
.flash{padding:10px 12px;border:1px solid #5b3c48;background:#281923;border-radius:9px;margin:12px 0}
</style></head><body><main class="card">
<img class="logo" src="{{ url_for('static',filename='postguard_logo.jpg') }}" alt="PostGuard">
<h1>{{ title }}</h1><p class="muted">{{ message }}</p>
{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}{% endwith %}
{% if form_kind == 'forgot' %}
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Email address</label><input name="email" type="email" required autocomplete="email">
<button class="btn">Send password reset link</button></form>
{% elif form_kind == 'reset' %}
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>New password</label><input name="password" type="password" minlength="12" required autocomplete="new-password">
<label>Confirm new password</label><input name="confirm" type="password" minlength="12" required autocomplete="new-password">
<button class="btn">Set new password</button></form>
{% elif form_kind == 'mfa_setup' %}
<p class="muted">Scan this QR code with your authenticator app, then enter the 6-digit code it generates.</p>
<div style="display:grid;place-items:center;margin:18px 0 14px">
  <div style="background:#fff;padding:12px;border-radius:14px;line-height:0">
    <img src="data:image/png;base64,{{ qr_png }}" alt="PostGuard MFA QR code" style="width:220px;height:220px;display:block">
  </div>
</div>
<p class="muted" style="text-align:center">Account: {{ session.get('email') }}</p>
<details style="margin:16px 0;color:#9aabc2">
  <summary style="cursor:pointer">Can't scan the QR code?</summary>
  <p class="muted">Enter this setup key manually in your authenticator app:</p>
  <p><strong style="word-break:break-all;color:#fff">{{ secret }}</strong></p>
</details>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>6-digit authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
<button class="btn">Enable MFA</button></form>
{% elif form_kind == 'mfa' %}
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>6-digit authenticator code</label><input name="code" inputmode="numeric" pattern="[0-9]{6}" required autofocus>
<button class="btn">Verify and continue</button></form>
{% elif action_url %}
<form method="post" action="{{ action_url }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button class="btn">{{ action_label }}</button></form>
{% endif %}
{% if back_url %}<p><a class="btn" href="{{ back_url }}">Back</a></p>{% endif %}
</main></body></html>
"""


@app.get("/verify-email/<token>")
@limiter.limit("10 per minute")
def verify_email(token):
    row = consume_auth_token(token, "verify_email")
    if not row:
        return render_template_string(
            SIMPLE_AUTH_PAGE,
            title="Verification link invalid",
            message="This verification link is invalid, expired or has already been used.",
            form_kind=None, action_url=None, action_label=None,
            back_url=url_for("login"),
        ), 400
    c = db()
    c.execute("UPDATE users SET email_verified=1 WHERE id=?", (row["user_id"],))
    c.commit()
    c.close()
    security_event("email_verified", True, row["user_id"])

    # End any stale pre-verification browser session so the customer cannot
    # be bounced back to the verification notice after clicking the email link.
    session.clear()
    session.permanent = True
    flash("Email verified successfully. Sign in to start your 7-day PostGuard demo.")
    return redirect(url_for("login", verified="1"), code=303)


@app.get("/verify-email")
@auth
def verify_email_notice():
    return render_template_string(
        SIMPLE_AUTH_PAGE,
        title="Verify your email",
        message="Your PostGuard account is waiting for email verification. "
                "Use the verification link sent to your registered email address.",
        form_kind=None,
        action_url=url_for("resend_verification"),
        action_label="Resend verification email",
        back_url=None,
    )


@app.post("/verify-email/resend")
@auth
@limiter.limit("3 per 15 minutes")
def resend_verification():
    c = db()
    user = c.execute(
        "SELECT id,email,email_verified FROM users WHERE id=?",
        (session["uid"],),
    ).fetchone()
    c.close()
    if not user:
        abort(404)
    if user["email_verified"] == 1:
        return redirect(url_for("home"))
    try:
        sent = send_verification_email(user["id"], user["email"])
    except Exception:
        app.logger.exception("Verification email resend failed")
        sent = False
    flash("Verification email sent." if sent else "Email service is not configured.")
    return redirect(url_for("verify_email_notice"))


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        c = db()
        user = c.execute(
            "SELECT id,email FROM users WHERE email=? AND enabled=1",
            (email,),
        ).fetchone()
        c.close()
        if user:
            try:
                send_password_reset_email(user["id"], user["email"])
            except Exception:
                app.logger.exception("Password reset email failed")
            security_event("password_reset_requested", True, user["id"])
        else:
            security_event("password_reset_requested", False, None)
        flash("If that account exists, a password reset email has been sent.")
    return render_template_string(
        SIMPLE_AUTH_PAGE,
        title="Reset your password",
        message="Enter the email address registered with PostGuard.",
        form_kind="forgot", action_url=None, action_label=None,
        back_url=url_for("login"),
    )


@app.route("/forgot-password/<token>", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def forgot_password_token(token):
    token_hash = _hash_token(token)
    c = db()
    row = c.execute(
        """
        SELECT * FROM auth_tokens
        WHERE token_hash=? AND kind='password_reset' AND used_at IS NULL
        ORDER BY id DESC LIMIT 1
        """,
        (token_hash,),
    ).fetchone()
    c.close()
    valid = bool(row and _iso_to_dt(row["expires_at"])
                 and _iso_to_dt(row["expires_at"]) >= datetime.now(timezone.utc))
    if not valid:
        return render_template_string(
            SIMPLE_AUTH_PAGE,
            title="Reset link invalid",
            message="This password reset link is invalid, expired or already used.",
            form_kind=None, action_url=None, action_label=None,
            back_url=url_for("forgot_password"),
        ), 400

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < 12:
            flash("Password must be at least 12 characters.")
        elif password != confirm:
            flash("Passwords do not match.")
        else:
            consumed = consume_auth_token(token, "password_reset")
            if not consumed:
                flash("That reset link is no longer valid.")
            else:
                c = db()
                c.execute(
                    "UPDATE users SET password=?, reset_required=0 WHERE id=?",
                    (generate_password_hash(password), consumed["user_id"]),
                )
                c.commit()
                c.close()
                security_event("password_reset_completed", True, consumed["user_id"])
                session.clear()
                flash("Password changed. Sign in with your new password.")
                return redirect(url_for("login"))

    return render_template_string(
        SIMPLE_AUTH_PAGE,
        title="Choose a new password",
        message="Use a new password of at least 12 characters.",
        form_kind="reset", action_url=None, action_label=None, back_url=None,
    )


def _mfa_qr_png(secret, account_email):
    label = quote(f"PostGuard:{account_email}", safe="")
    issuer = quote("PostGuard", safe="")
    uri = (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
    qr = qrcode.QRCode(version=None, box_size=8, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


@app.route("/mfa/setup", methods=["GET", "POST"])
@auth
@limiter.limit("8 per 10 minutes", methods=["POST"])
def mfa_setup():
    if session.get("role") != "admin":
        abort(403)
    c = db()
    row = c.execute(
        "SELECT mfa_secret,mfa_enabled FROM users WHERE id=?",
        (session["uid"],),
    ).fetchone()
    if not row:
        c.close()
        abort(404)
    if row["mfa_enabled"] == 1:
        c.close()
        return redirect(url_for("mfa_challenge"))

    # Issue a fresh setup secret once per admin login session. This deliberately
    # rotates any previously displayed but not-yet-enabled secret before enrolment.
    if not session.get("mfa_setup_secret_issued"):
        secret = _totp_secret()
        c.execute("UPDATE users SET mfa_secret=? WHERE id=?", (secret, session["uid"]))
        c.commit()
        session["mfa_setup_secret_issued"] = True
    else:
        secret = row["mfa_secret"] or _totp_secret()
        if not row["mfa_secret"]:
            c.execute("UPDATE users SET mfa_secret=? WHERE id=?", (secret, session["uid"]))
            c.commit()
    c.close()

    if request.method == "POST":
        if verify_totp(secret, request.form.get("code", "")):
            c = db()
            c.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (session["uid"],))
            c.commit()
            c.close()
            security_event("mfa_enabled", True, session["uid"])
            session["mfa_pending"] = False
            session["mfa_verified_at"] = now()
            session.pop("mfa_setup_secret_issued", None)
            flash("Multi-factor authentication enabled.")
            return redirect(url_for("home"))
        security_event("mfa_setup", False, session["uid"])
        flash("Invalid authenticator code.")

    return render_template_string(
        SIMPLE_AUTH_PAGE,
        title="Secure Admin with MFA",
        message="PostGuard requires an authenticator-app code for production Admin access.",
        form_kind="mfa_setup", secret=secret,
        qr_png=_mfa_qr_png(secret, session.get("email", "admin")),
        action_url=None, action_label=None, back_url=None,
    )


@app.route("/mfa/challenge", methods=["GET", "POST"])
@auth
@limiter.limit("8 per 10 minutes", methods=["POST"])
def mfa_challenge():
    if session.get("role") != "admin":
        abort(403)
    c = db()
    row = c.execute(
        "SELECT mfa_secret,mfa_enabled FROM users WHERE id=?",
        (session["uid"],),
    ).fetchone()
    c.close()
    if not row or row["mfa_enabled"] != 1 or not row["mfa_secret"]:
        return redirect(url_for("mfa_setup"))

    if request.method == "POST":
        if verify_totp(row["mfa_secret"], request.form.get("code", "")):
            session["mfa_pending"] = False
            session["mfa_verified_at"] = now()
            c = db()
            c.execute("UPDATE users SET last_login_at=? WHERE id=?", (now(), session["uid"]))
            c.commit()
            c.close()
            security_event("mfa_challenge", True, session["uid"])
            return redirect(url_for("home"))
        security_event("mfa_challenge", False, session["uid"])
        flash("Invalid authenticator code.")

    return render_template_string(
        SIMPLE_AUTH_PAGE,
        title="Admin verification",
        message="Enter the current 6-digit code from your authenticator app.",
        form_kind="mfa", action_url=None, action_label=None, back_url=None,
    )


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
.sidebar{display:flex;flex-direction:column;background:#0d1525;border-right:1px solid #22304a;padding:24px 18px}
.brand{font-size:1.25rem;font-weight:800;letter-spacing:.03em;margin-bottom:28px}
.brand span{color:#8cb4ff}
.nav{display:flex;flex-direction:column;display:grid;gap:8px}
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
@media(max-width:980px){.shell{grid-template-columns:1fr}.sidebar{display:flex;flex-direction:column;display:none}.cards{grid-template-columns:repeat(2,1fr)}.section-grid{grid-template-columns:1fr}}
@media(max-width:600px){.main{padding:18px}.cards{grid-template-columns:1fr}}


.sidebar-logo-wrap{
    margin-top:auto;
    padding:18px 10px 8px;
    display:flex;
    justify-content:center;
}
.sidebar-logo{
    width:110px;
    height:110px;
    border-radius:50%;
    object-fit:cover;
    border:1px solid rgba(135,173,255,.34);
    box-shadow:0 14px 38px rgba(0,0,0,.30);
}
@media(max-width:800px){
    .sidebar-logo{width:88px;height:88px}
}

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
    
        <div class="sidebar-logo-wrap">
            <img class="sidebar-logo" src="{{ url_for('static', filename='postguard_logo.jpg') }}" alt="PostGuard">
        </div>
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
def home():
    # Public visitors see pricing first. Existing authenticated users keep their dashboard.
    if "uid" not in session:
        return render_template_string(PAID_SPLASH_PAGE, plans=PLANS, payments_ready=stripe_configured(), promo_ready=free_access_promo_configured())

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
.sidebar{display:flex;flex-direction:column;background:#0d1525;border-right:1px solid #22304a;padding:24px 18px}
.brand{font-size:1.25rem;font-weight:800;letter-spacing:.03em;margin-bottom:28px}
.brand span{color:#8cb4ff}
.nav{display:flex;flex-direction:column;display:grid;gap:8px}
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
@media(max-width:850px){.shell{grid-template-columns:1fr}.sidebar{display:flex;flex-direction:column;display:none}.grid{grid-template-columns:1fr}}


.sidebar-logo-wrap{
    margin-top:auto;
    padding:18px 10px 8px;
    display:flex;
    justify-content:center;
}
.sidebar-logo{
    width:110px;
    height:110px;
    border-radius:50%;
    object-fit:cover;
    border:1px solid rgba(135,173,255,.34);
    box-shadow:0 14px 38px rgba(0,0,0,.30);
}
@media(max-width:800px){
    .sidebar-logo{width:88px;height:88px}
}

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
    
        <div class="sidebar-logo-wrap">
            <img class="sidebar-logo" src="{{ url_for('static', filename='postguard_logo.jpg') }}" alt="PostGuard">
        </div>
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
            decisionTitle.textContent = "🟢 LOW RISK — NO SIGNIFICANT RISKS DETECTED";
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
        <div class="decision safe">🟢 LOW RISK — NO SIGNIFICANT RISKS DETECTED</div>
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
            <div class="safe" style="margin-top:8px;font-weight:800">🟢 LOW RISK — NO SIGNIFICANT RISKS DETECTED</div>
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
            <div class="safe" style="margin-top:7px;font-weight:800">🟢 LOW RISK — NO SIGNIFICANT RISKS DETECTED</div>
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

</style></head><body>
<main>
<div class="actions">
<a class="btn" href="{{ url_for('home') }}">← Dashboard</a>
<form method="post" action="{{ url_for('logout') }}" style="margin:0">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button class="btn" type="submit">Log out</button>
</form>
</div>
<h1>My Account</h1>
{% with messages=get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<div class="card"><h2>Account details</h2><p><strong>Email:</strong> {{ user["email"] }}</p><p><strong>Account type:</strong> {{ user["role"] or "user" }}</p><p><strong>Registered:</strong> {{ user["created_at"] or "—" }}</p>
<p><a href="{{ url_for('privacy_page') }}">Privacy Notice</a> · <a href="{{ url_for('data_retention_page') }}">Data Retention</a> · <a href="{{ url_for('terms_page') }}">Terms of Service</a></p></div>
{% if user["role"] != "admin" %}<div class="card"><h2>Subscription</h2><p><strong>Plan:</strong> {{ user["subscription_plan"] or "—" }}</p><p><strong>Status:</strong> {{ user["subscription_status"] or "—" }}</p>{% if user["trial_ends_at"] %}<p><strong>Trial ends:</strong> {{ user["trial_ends_at"] }}</p>{% endif %}{% if user["subscription_plan"] == "promo" %}<p class="muted">Complimentary promo access. No recurring Stripe subscription is attached to this access.</p>{% else %}<p class="muted">Your selected plan automatically renews monthly after the 7-day free trial unless you cancel before the trial ends.</p>{% endif %}{% if user["stripe_customer_id"] %}<form method="post" action="{{ url_for('billing_portal') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn" type="submit">Manage or cancel subscription</button></form>{% endif %}</div>{% endif %}
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

</style></head><body>
<div class="panel"><h1>Delete my account</h1>
<p class="warning"><strong>This is permanent.</strong> Your PostGuard account and PostGuard-owned customer data will be deleted.</p>
<p class="muted">To confirm, type your email address and current password.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Email</label><input name="confirm_email" type="email" autocomplete="off" required>
<label>Current password</label><input name="password" type="password" autocomplete="current-password" required>
<button class="btn danger" type="submit" onclick="return confirm('Permanently delete your PostGuard account?')">Permanently delete my account</button>
<a class="btn" href="{{ url_for('account') }}">Cancel</a></form></div></body></html>
"""



def stripe_webhook_secret():
    return os.getenv("POSTGUARD_STRIPE_WEBHOOK_SECRET", "").strip()

def verify_stripe_signature(payload, signature_header):
    secret = stripe_webhook_secret()
    if not secret or not signature_header:
        return False
    parts = {}
    for item in signature_header.split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            parts.setdefault(k.strip(), []).append(v.strip())
    try:
        timestamp = int((parts.get("t") or [""])[0])
    except ValueError:
        return False
    if abs(int(time.time()) - timestamp) > 300:
        return False
    signed = str(timestamp).encode() + b"." + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in parts.get("v1", []))

@app.post("/stripe/webhook")
@csrf.exempt
def stripe_webhook():
    payload = request.get_data(cache=False)
    if not verify_stripe_signature(payload, request.headers.get("Stripe-Signature", "")):
        return "invalid signature", 400
    try:
        event = json.loads(payload.decode("utf-8"))
    except Exception:
        return "invalid payload", 400
    event_type = event.get("type", "")
    obj = ((event.get("data") or {}).get("object") or {})
    if event_type.startswith("customer.subscription."):
        sub_id = obj.get("id")
        customer_id = obj.get("customer")
        status = obj.get("status") or "unknown"
        trial_end = obj.get("trial_end")
        trial_iso = datetime.fromtimestamp(int(trial_end), tz=timezone.utc).isoformat() if trial_end else None
        c = db()
        c.execute("UPDATE users SET subscription_status=?, trial_ends_at=?, stripe_customer_id=COALESCE(stripe_customer_id,?) WHERE stripe_subscription_id=?", (status, trial_iso, customer_id, sub_id))
        c.commit(); c.close()
    return "ok", 200

@app.post("/account/billing")
@auth
@limiter.limit("10 per minute")
def billing_portal():
    c=db(); user=c.execute("SELECT role,stripe_customer_id FROM users WHERE id=?",(session["uid"],)).fetchone(); c.close()
    if not user or user["role"] == "admin" or not user["stripe_customer_id"]:
        flash("No Stripe subscription is linked to this account.")
        return redirect(url_for("account"))
    public_url=os.getenv("POSTGUARD_PUBLIC_URL", "").strip().rstrip("/")
    try:
        portal=stripe_api("POST", "/v1/billing_portal/sessions", {"customer": user["stripe_customer_id"], "return_url": public_url + "/account"})
        if not portal.get("url"):
            raise RuntimeError("Stripe did not return a billing portal URL")
        return redirect(portal["url"])
    except Exception:
        app.logger.exception("Unable to create Stripe billing portal session")
        flash("Subscription management is temporarily unavailable. Please try again shortly.")
        return redirect(url_for("account"))

@app.get("/account")
@auth
def account():
    c=db()
    user=c.execute("SELECT id,email,role,created_at,subscription_plan,subscription_status,trial_ends_at,stripe_customer_id,stripe_subscription_id FROM users WHERE id=?",(session["uid"],)).fetchone()
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
        # One-use verification/reset tokens are customer account data and are removed immediately.
        c.execute("DELETE FROM auth_tokens WHERE user_id=?",(uid,))
        # Security events are deliberately retained under the 12-month security-log policy.
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
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PostGuard Admin · Customer</title><style>:root{color-scheme:dark}body{margin:0;font-family:system-ui,sans-serif;background:#0b1020;color:#f5f7fb}header,main{padding:24px 28px}header{border-bottom:1px solid #26314a}.muted{color:#aeb9ce}.btn{display:inline-block;padding:8px 11px;border:1px solid #394762;border-radius:8px;background:#151c2f;color:inherit;text-decoration:none}.table{overflow-x:auto;background:#151c2f;border:1px solid #26314a;border-radius:14px;margin:12px 0 24px}table{width:100%;border-collapse:collapse;min-width:720px}th,td{padding:11px 13px;text-align:left;border-bottom:1px solid #26314a}th{color:#aeb9ce;font-size:.8rem;text-transform:uppercase}
</style></head><body>
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
        # One-use verification/reset tokens are customer account data and are removed immediately.
        c.execute("DELETE FROM auth_tokens WHERE user_id=?", (user_id,))
        # Security events are deliberately retained under the 12-month security-log policy.
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
# PUBLIC PRIVACY / TERMS / RETENTION INFORMATION
# Launch drafts: obtain qualified UK legal/privacy review before commercial launch.
# ============================================================

LEGAL_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PostGuard · {{ title }}</title><style>
:root{color-scheme:dark}body{margin:0;font-family:system-ui,sans-serif;background:#07101d;color:#f6f8fb}
main{width:min(920px,calc(100% - 32px));margin:40px auto;background:#0d1828;border:1px solid #243754;border-radius:16px;padding:28px}
img{width:88px;height:88px;border-radius:50%;object-fit:cover}h1,h2,h3{color:#fff}.muted,p,li,td,th{color:#b6c3d4;line-height:1.65}
a{color:#a9c5ff}.notice{border:1px solid #705d34;background:#261f11;padding:12px;border-radius:9px}.meta{color:#8fa1b8;font-size:.93rem}
table{width:100%;border-collapse:collapse;margin:16px 0}th,td{border:1px solid #243754;padding:10px;text-align:left;vertical-align:top}th{color:#fff;background:#111f33}
</style></head><body><main>
<img src="{{ url_for('static',filename='postguard_logo.jpg') }}" alt="PostGuard">
<h1>{{ title }}</h1>
<p class="meta">Effective: 4 September 2026 · Version 1.0</p>
<div class="notice"><strong>Launch draft.</strong> This document reflects PostGuard's current product design and privacy decisions, but must be reviewed and approved by qualified UK legal/privacy counsel before commercial launch.</div>
{{ body|safe }}
<p><a href="{{ url_for('login') }}">Return to PostGuard</a> · <a href="{{ url_for('privacy_page') }}">Privacy</a> · <a href="{{ url_for('terms_page') }}">Terms</a> · <a href="{{ url_for('data_retention_page') }}">Data retention</a></p>
</main></body></html>
"""

@app.get("/privacy")
def privacy_page():
    body = """
    <h2>1. Who we are</h2>
    <p>PostGuard is currently operated as a pre-incorporation business in the United Kingdom. For the purposes of this launch draft, PostGuard determines why and how personal information is used when providing the PostGuard service.</p>
    <p>Website: <a href="https://www.postguard.uk">www.postguard.uk</a><br>Security and privacy contact: <a href="mailto:security@postguard.uk">security@postguard.uk</a></p>

    <h2>2. Who may use PostGuard</h2>
    <p>You must be at least 16 years old to create and use a PostGuard account. PostGuard is not intended for accounts belonging to children under 16.</p>

    <h2>3. Information we process</h2>
    <p>Depending on how you use PostGuard, we may process account information such as your email address and account settings; authentication and security records; captions, text, images and metadata you choose to submit for a PostGuard check; scan results, risk scores, findings and safer-post suggestions; alerts, cases and notes; and technical information used to protect the service, such as a privacy-protective hash derived from an IP address and a limited user-agent record.</p>
    <p>Passwords are not stored in readable form. PostGuard stores password hashes. The current scanner processes uploaded images temporarily and is not designed to retain the uploaded image as permanent media after the scan.</p>

    <h2>4. Why we use information and our lawful bases</h2>
    <table><tr><th>Purpose</th><th>Typical lawful basis</th></tr>
    <tr><td>Create and manage your account and provide requested PostGuard scanning, alerts, cases and account features.</td><td>Contract.</td></tr>
    <tr><td>Protect accounts and systems, investigate abuse, maintain security records, prevent fraud and diagnose security incidents.</td><td>Legitimate interests, where those interests are not overridden by your rights and interests.</td></tr>
    <tr><td>Send optional promotional or marketing communications.</td><td>Consent. Marketing is opt-in and you may withdraw consent.</td></tr>
    <tr><td>Keep or disclose information where applicable law requires us to do so.</td><td>Legal obligation.</td></tr></table>
    <p>Where PostGuard relies on legitimate interests, the interests include protecting customers, maintaining the integrity and security of the service, preventing misuse and investigating security incidents. PostGuard should document the relevant balancing assessment for production processing.</p>

    <h2>5. Post checks, risk scoring and automated processing</h2>
    <p>PostGuard automatically analyses submitted content and may generate a risk score, findings, recommendations and a publishing decision such as LOW RISK — NO SIGNIFICANT RISKS DETECTED, REVIEW BEFORE POSTING or DO NOT POST. The current service is a decision-support tool: a low-risk result is not a guarantee that content is safe, and the user remains responsible for deciding whether to publish.</p>
    <p>PostGuard does not currently intend these risk recommendations to make legal or similarly significant decisions about a person. If the product changes so that automated processing has legal or similarly significant effects, PostGuard will reassess the applicable safeguards and privacy information before that use begins.</p>

    <h2>6. Images, posts and AI training</h2>
    <p>You retain your rights in content you submit. PostGuard processes submitted content to provide the security/privacy service and related account functions. PostGuard does <strong>not</strong> use customer posts, images or scan content to train AI models. A future change to that position would require a separate assessment and appropriate transparency and, where required, consent before the new use begins.</p>

    <h2>7. Service providers and sharing</h2>
    <p>PostGuard may use carefully selected service providers acting on our behalf for hosting, databases, transactional email, security, monitoring and other infrastructure needed to operate the service. We limit sharing to what is reasonably necessary for the relevant purpose and expect appropriate contractual and security safeguards.</p>
    <p>We may also disclose information where required by law, to establish or defend legal claims, or where necessary to protect the security of users or the service and a lawful basis permits the disclosure.</p>

    <h2>8. International transfers</h2>
    <p>Some service providers may process information outside the UK. Where UK data-protection law requires a transfer safeguard, PostGuard will use an applicable UK transfer mechanism or other lawful safeguard and will provide further information about relevant safeguards on request.</p>

    <h2>9. How long we keep information</h2>
    <p>Account and customer workspace data is retained while needed to provide an active account, subject to the deletion controls described below and any justified legal requirement. Authentication tokens are short-lived and one-use, and are removed with the account. Security-event records are retained for up to 12 months unless longer retention is genuinely necessary for an active investigation or legal obligation.</p>
    <p>When an account is deleted, PostGuard deletes customer-controlled database records covered by the account-deletion workflow. Limited security records may remain for the stated security retention period. Deleted information may also remain temporarily in protected backups until it expires under the backup lifecycle. See the <a href="/data-retention">Data Retention Policy</a>.</p>

    <h2>10. Your data-protection rights</h2>
    <p>Depending on the circumstances and lawful basis, UK data-protection law may give you rights to request access, correction, erasure, restriction, objection and data portability, and to withdraw consent where processing relies on consent. Withdrawal does not affect processing that was lawful before withdrawal.</p>
    <p><strong>Your right to object:</strong> where PostGuard relies on legitimate interests, you may have the right to object to that processing. You can contact <a href="mailto:security@postguard.uk">security@postguard.uk</a> to exercise applicable rights.</p>

    <h2>11. Marketing</h2>
    <p>PostGuard marketing is opt-in only. Creating an account does not by itself subscribe you to promotional marketing. Essential service and security messages, such as verification, password-reset and important account/security notices, are separate from marketing.</p>

    <h2>12. Special-category and third-party information</h2>
    <p>PostGuard is not launching on the basis that it intentionally needs large-scale special-category personal data. Users should avoid submitting unnecessary sensitive information or information about other people. Before PostGuard intentionally introduces processing that requires a special-category condition, it will assess and document the appropriate UK GDPR and Data Protection Act requirements.</p>

    <h2>13. Security</h2>
    <p>PostGuard uses technical and organisational safeguards designed to protect account information, including password hashing, secure sessions, CSRF protection, rate limiting, email verification, administrator multi-factor authentication and database recovery controls. No internet service can guarantee absolute security.</p>

    <h2>14. Complaints</h2>
    <p>Please contact <a href="mailto:security@postguard.uk">security@postguard.uk</a> if you have a privacy concern. You also have the right to complain to the UK Information Commissioner's Office (ICO). See <a href="https://ico.org.uk/make-a-complaint/data-protection-complaints/">ICO data-protection complaints guidance</a>.</p>

    <h2>15. Changes to this notice</h2>
    <p>PostGuard may update this notice as the service changes. Material changes to how personal information is used should be brought to users' attention before the new processing begins where required.</p>
    """
    return render_template_string(LEGAL_PAGE,title="Privacy Notice",body=body)

@app.get("/terms")
def terms_page():
    body = """
    <p><strong>Effective date: 4 September 2026.</strong> These Terms are a launch draft and should receive qualified UK legal review before PostGuard accepts paying customers.</p>

    <h2>1. About PostGuard and these Terms</h2>
    <p>PostGuard is currently operated as a pre-incorporation business in the United Kingdom. Website: www.postguard.uk. These Terms govern access to and use of the PostGuard service. You must be at least 16 years old to create and use a PostGuard account.</p>

    <h2>2. Service purpose and advisory nature</h2>
    <p>PostGuard analyses content supplied by users to identify potential privacy, personal-security and information-disclosure risks. Risk scores, warnings, alerts, recommendations, safer-post suggestions and publishing guidance are decision-support tools only. They are not legal advice, law-enforcement advice, approval of content, or a guarantee that content is safe, lawful or free from risk.</p>
    <p><strong>The final decision whether to create, publish, share, repost or otherwise make content available online remains with the user.</strong> A LOW RISK result or an absence of warnings does not mean PostGuard has approved the content or guaranteed that publication will have no adverse consequences.</p>

    <h2>3. User responsibility</h2>
    <p>Users are responsible for the content they choose to publish and for ensuring that their use of social-media platforms and published content complies with applicable law, regulations, third-party rights and platform rules. To the extent permitted by law, PostGuard is not responsible for criminal proceedings, civil claims, reputational consequences, platform enforcement or other consequences arising solely from content a user chooses to publish where those consequences were not caused by PostGuard's breach of its legal obligations.</p>

    <h2>4. Acceptable use</h2>
    <p>You must not use PostGuard to commit, encourage or facilitate unlawful activity; threaten, harass, stalk or deliberately endanger another person; impersonate or defraud another person; violate privacy or intellectual-property rights; submit content you have no lawful right to provide; interfere with, attack, reverse-engineer or abuse the service; or attempt to bypass PostGuard security, account controls or access restrictions, except where applicable law provides a right that cannot lawfully be restricted.</p>

    <h2>5. Account security</h2>
    <p>You must keep your credentials confidential, provide accurate account information, avoid sharing access with unauthorised people, and promptly report suspected compromise to <a href="mailto:security@postguard.uk">security@postguard.uk</a>. PostGuard remains responsible for taking reasonable measures to secure its own systems.</p>

    <h2>6. Your content</h2>
    <p>You retain ownership of posts, captions, photographs, images and other content you submit. PostGuard does not claim ownership of your content. You give PostGuard only the limited permission reasonably necessary to receive, store, process and analyse that content to provide and secure the service. Customer posts, images and scan content are not used to train AI models under PostGuard's current policy. You are responsible for having the rights or permission necessary to submit content, including content concerning another person.</p>

    <h2>7. PostGuard intellectual property</h2>
    <p>PostGuard retains its rights in its software and source code, name, branding and logos, website and interface design, security-analysis and risk-scoring systems, reports, templates, documentation, proprietary methods and technology. While your account is active, you receive a limited, non-exclusive, non-transferable right to use the service for its intended purpose. You may not copy, resell, sublicense, reverse-engineer or commercially exploit PostGuard except where applicable law provides a right that cannot lawfully be restricted.</p>

    <h2>8. Availability and service changes</h2>
    <p>PostGuard aims to provide a reliable and secure service but does not guarantee uninterrupted, error-free or continuously available access. Maintenance, security work, technical faults, third-party infrastructure failures or circumstances outside PostGuard's reasonable control may cause interruptions. PostGuard may reasonably update features for security, functionality, legal compliance or operation of the service. Where a change materially disadvantages a paying customer, reasonable notice will be provided where practicable and applicable consumer rights will be respected.</p>

    <h2>9. Suspension and termination</h2>
    <p>PostGuard may restrict or suspend an account where reasonably necessary to investigate compromise, protect users or the service, prevent unlawful activity, comply with legal obligations or address a material breach. Less serious breaches should normally receive notice and a reasonable opportunity to be corrected where appropriate. Serious security threats, fraud, unlawful activity or repeated material breaches may justify immediate suspension or termination. Customers may close their account using the account-deletion facility. Deletion and retention follow the Privacy Notice and Data Retention Policy.</p>

    <h2>10. Liability</h2>
    <p>PostGuard is a security and privacy decision-support service. It is not responsible for risks it could not reasonably identify from the information supplied. The user remains responsible for the final publishing decision. To the extent permitted by law, PostGuard is not responsible for criminal proceedings, civil claims, reputational damage, social-media enforcement or other consequences arising from a user's publishing decision, except to the extent a loss was caused by PostGuard's breach of a legal obligation or another liability that cannot lawfully be excluded.</p>
    <p>Nothing in these Terms excludes or limits liability that cannot lawfully be excluded or limited, or affects applicable consumer statutory rights, including rights concerning services supplied with reasonable care and skill.</p>

    <h2>11. Plans, prices and payment</h2>
    <table><tr><th>Plan</th><th>Monthly price</th></tr><tr><td>PostGuard Personal</td><td>£49/month</td></tr><tr><td>PostGuard Executive</td><td>£199/month</td></tr><tr><td>PostGuard VIP</td><td>£300/month</td></tr></table>
    <p><strong>7-day free trial:</strong> A payment method is required. Unless you cancel before the 7-day trial ends, the selected monthly fee is charged automatically and the subscription continues to renew monthly until cancelled. You can manage or cancel your subscription through the account billing portal.</p>
    <p>The features included in each plan are those clearly displayed at the point of purchase. Before a paid subscription is created, PostGuard will display the price, billing period and applicable renewal and cancellation information. Recurring subscriptions may automatically renew where this is clearly disclosed and agreed. PostGuard will not introduce hidden charges. Material price changes affecting an existing subscription will be communicated in advance where required. Applicable UK consumer cancellation, refund and cooling-off rights will be respected. Cancelling a paid subscription and deleting a PostGuard account are separate actions.</p>

    <h2>12. Governing law and disputes</h2>
    <p>These Terms are governed by the law of England and Wales, subject to any mandatory consumer protections and rights that apply based on where a customer lives. Customers are encouraged to contact <a href="mailto:security@postguard.uk">security@postguard.uk</a> so PostGuard has an opportunity to resolve a dispute, without removing the customer's right to pursue a claim or other remedy.</p>

    <h2>13. Changes to these Terms</h2>
    <p>PostGuard may update these Terms where reasonably necessary because of changes to the service, security requirements, applicable law, regulatory requirements or business operations. Where a change materially affects existing customers' rights or obligations, PostGuard will provide reasonable advance notice where practicable, for example by email or an in-service notice. The current version and effective date will remain available on the website. Where applicable law requires explicit consent or provides cancellation rights, those requirements will be respected.</p>

    <h2>14. Contact</h2>
    <p>Questions about these Terms or security concerns can be sent to <a href="mailto:security@postguard.uk">security@postguard.uk</a>.</p>
    """
    return render_template_string(LEGAL_PAGE,title="Terms of Service",body=body)

@app.get("/data-retention")
def data_retention_page():
    body = """
    <h2>Account and workspace data</h2><p>Account information, scans, alerts, cases and associated workspace records are kept while needed to provide an active account, unless the user deletes the account or a different legal requirement applies.</p>
    <h2>Account deletion</h2><p>The account-deletion workflow removes customer-owned alerts, cases, checks, principals/profile records, customer audit records, one-use authentication tokens and the user account. Security-event records are treated separately as security logs.</p>
    <h2>Security logs</h2><p>Security-event records are retained for up to <strong>12 months</strong> and are automatically pruned as new security events are recorded. A record may be kept longer where genuinely necessary for an active security investigation or legal obligation; production procedures should document any such exception.</p>
    <h2>Uploaded images</h2><p>The current scan workflow processes uploaded images temporarily and is not designed to retain the uploaded media permanently after analysis. Scan findings and associated database records may remain in the customer's workspace.</p>
    <h2>Backups</h2><p>Deleted information can remain temporarily in protected database backups until those backups expire under the infrastructure backup lifecycle. PostGuard has production database export and point-in-time recovery capability; backup retention is governed by the configured infrastructure plan.</p>
    <h2>Review</h2><p>This schedule must be reviewed as PostGuard adds new data categories, social-media integrations, AI providers, support systems or other processors.</p>
    """
    return render_template_string(LEGAL_PAGE,title="Data Retention Policy",body=body)

# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify(
        status="ok",
        service="postguard",
        version="7.6.5",
    )


@app.get("/ready")
def ready():
    checks = {
        "production_secret": (not IS_PRODUCTION) or len(os.getenv("POSTGUARD_SECRET", "")) >= 32,
        "postgresql": bool(os.getenv("DATABASE_URL")) if IS_PRODUCTION else True,
        "public_https_url": bool(os.getenv("POSTGUARD_PUBLIC_URL")) if IS_PRODUCTION else True,
        "transactional_email": _smtp_configured() if IS_PRODUCTION else True,
        "admin_mfa_required": admin_mfa_required() if IS_PRODUCTION else True,
        "database_backups_confirmed": os.getenv("POSTGUARD_BACKUPS_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
        "restore_test_confirmed": os.getenv("POSTGUARD_RESTORE_TEST_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
        "legal_review_confirmed": os.getenv("POSTGUARD_LEGAL_REVIEW_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
        "security_test_confirmed": os.getenv("POSTGUARD_SECURITY_TEST_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
        "monitoring_confirmed": os.getenv("POSTGUARD_MONITORING_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
        "vision_ai_confirmed": os.getenv("POSTGUARD_VISION_AI_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
        "social_oauth_confirmed": os.getenv("POSTGUARD_SOCIAL_OAUTH_CONFIRMED", "0") == "1" if IS_PRODUCTION else True,
    }
    ok = all(checks.values())
    return jsonify(
        status="ready" if ok else "not_ready",
        service="postguard",
        version="7.6.5",
        checks=checks,
    ), 200 if ok else 503


# ============================================================
# STARTUP
# ============================================================

if IS_PRODUCTION:
    if not os.getenv("DATABASE_URL"):
        raise RuntimeError("DATABASE_URL is required in production.")
    public_url = os.getenv("POSTGUARD_PUBLIC_URL", "").strip()
    if not public_url.startswith("https://"):
        raise RuntimeError("POSTGUARD_PUBLIC_URL must be an https:// URL in production.")

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