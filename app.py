import os
import re
import json
import secrets
import sqlite3

import psycopg
from psycopg.rows import dict_row

from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)

from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ExifTags


# ============================================================
# PATHS / APP
# ============================================================

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
DB = os.path.join(DATA, "postguard.db")
UP = os.path.join(DATA, "uploads")

os.makedirs(UP, exist_ok=True)

app = Flask(__name__)

app.secret_key = os.getenv(
    "POSTGUARD_SECRET",
    secrets.token_hex(32),
)

app.config.update(
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


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
            score INTEGER,
            risk TEXT,
            findings TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY,
            principal_id INTEGER,
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
# AUTHENTICATION
# ============================================================

def auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))

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
        r"\b(home|house|my place|front door|garden|bedroom|back home)\b",
        28,
        "Location / property exposure",
        "The caption may reveal a private location.",
        "Remove location clues and identifiable property details.",
        "HIGH",
    ),
    (
        r"\b(tomorrow|tonight|next week|flying|flight|airport|holiday|dubai|ibiza|abroad|away)\b",
        24,
        "Travel disclosure",
        "The caption may reveal current or future travel.",
        "Remove timing/location details and consider posting after travel.",
        "HIGH",
    ),
    (
        r"\b(kids|children|school|daughter|son|family)\b",
        16,
        "Family exposure",
        "Family information can increase privacy exposure.",
        "Remove unnecessary family details and identifiable context.",
        "MEDIUM",
    ),
    (
        r"\b(address|postcode|street|phone|number|email)\b",
        30,
        "Personal information",
        "The caption appears to contain direct personal-data clues.",
        "Remove personal contact/address information.",
        "HIGH",
    ),
    (
        r"\b(routine|every morning|every night|daily|usual|regularly)\b",
        18,
        "Routine exposure",
        "The caption may establish a predictable routine.",
        "Remove recurring timing or routine information.",
        "MEDIUM",
    ),
    (
        r"\b(password|passcode|pin|api key|secret|token)\b",
        45,
        "Credential exposure",
        "Caption contains language associated with secrets.",
        "Do not publish credentials or secret material.",
        "CRITICAL",
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
# Only the FIRST account may register.
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    c = db()

    user_exists = c.execute(
        "SELECT id FROM users LIMIT 1"
    ).fetchone()

    c.close()

    if user_exists:
        flash("Registration is closed.")
        return redirect(url_for("login"))

    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        confirm = request.form.get(
            "confirm",
            "",
        )

        if not email or not password:
            flash("Email and password are required.")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.")
            return render_template("register.html")

        if len(password) < 10:
            flash("Password must be at least 10 characters.")
            return render_template("register.html")

        c = db()

        existing = c.execute(
            "SELECT id FROM users WHERE email=?",
            (email,),
        ).fetchone()

        if existing:
            c.close()

            flash(
                "An account with that email already exists."
            )

            return render_template("register.html")

        c.execute(
            """
            INSERT INTO users(
                email,
                password,
                role,
                created_at
            )
            VALUES(?,?,?,?)
            """,
            (
                email,
                generate_password_hash(password),
                "admin",
                now(),
            ),
        )

        c.commit()
        c.close()

        flash(
            "Account created. You can now sign in."
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@app.route("/login", methods=["GET", "POST"])
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

        c.close()

        if user and check_password_hash(
            user["password"],
            password,
        ):
            session.clear()

            session["uid"] = user["id"]
            session["email"] = email

            return redirect(url_for("home"))

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

    caption = request.form.get(
        "caption",
        "",
    )

    score, findings = caption_scan(caption)

    uploaded_file = request.files.get("image")

    filename = None
    metadata = {}

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

    risk_level = risk(score)

    c = db()

    c.execute(
        """
        INSERT INTO checks(
            principal_id,
            filename,
            score,
            risk,
            findings,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            principal_id,
            filename,
            score,
            risk_level,
            json.dumps(findings),
            now(),
        ),
    )

    c.commit()
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
            name,
            role,
            created_at
        )
        VALUES(?,?,?)
        """,
        (
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

    c.execute(
        """
        UPDATE alerts
        SET status='Closed'
        WHERE id=?
        """,
        (alert_id,),
    )

    c.commit()
    c.close()

    audit(
        "close_alert",
        str(alert_id),
    )

    return jsonify(ok=True)


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
            title,
            owner,
            notes,
            created_at
        )
        VALUES(?,?,?,?)
        """,
        (
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

    c.execute(
        """
        UPDATE cases
        SET status='Closed'
        WHERE id=?
        """,
        (case_id,),
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
@auth
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
@auth
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
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify(
        status="ok",
        service="postguard",
        version="4.1",
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
