import os,re,json,secrets,sqlite3
import psycopg
from psycopg.rows import dict_row
from datetime import datetime
from functools import wraps
from flask import Flask,render_template,request,redirect,url_for,session,jsonify,flash
from werkzeug.security import generate_password_hash,check_password_hash
from PIL import Image,ImageDraw,ImageFilter,ExifTags

BASE=os.path.dirname(os.path.abspath(__file__)); DB=os.path.join(BASE,"data","postguard.db"); UP=os.path.join(BASE,"data","uploads")
os.makedirs(UP,exist_ok=True)
app = Flask(__name__)

app.secret_key = os.getenv(
    "POSTGUARD_SECRET",
    secrets.token_hex(32)
)

app.config.update(
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

def db():
    database_url = os.getenv("DATABASE_URL")

    if database_url:
        return psycopg.connect(
            database_url,
            row_factory=dict_row
        )

    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    c=db();c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,role TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS principals(id INTEGER PRIMARY KEY,name TEXT,role TEXT,risk INTEGER DEFAULT 0,created_at TEXT);
    CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY,principal_id INTEGER,filename TEXT,score INTEGER,risk TEXT,findings TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,principal_id INTEGER,severity TEXT,category TEXT,detail TEXT,recommendation TEXT,status TEXT DEFAULT 'Open',created_at TEXT);
    CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,title TEXT,status TEXT DEFAULT 'Open',owner TEXT,notes TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS sources(id INTEGER PRIMARY KEY,name TEXT,kind TEXT,status TEXT,notes TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT,detail TEXT,created_at TEXT);
    """)

    if not c.execute("SELECT 1 FROM principals LIMIT 1").fetchone():
        c.executemany(
            "INSERT INTO principals(name,role,risk,created_at) VALUES(?,?,?,?)",
            [
                ("Alex Morgan", "Professional Footballer", 63, datetime.utcnow().isoformat()),
                ("Jordan Lee", "Executive", 41, datetime.utcnow().isoformat())
            ]
        )
    if not c.execute("SELECT 1 FROM sources LIMIT 1").fetchone():
        c.executemany("INSERT INTO sources(name,kind,status,notes,created_at) VALUES(?,?,?,?,?)",[
            ("Client public profile feed","Authorised social source","Demo","Connector placeholder — no credentials stored.",datetime.utcnow().isoformat()),
            ("Impersonation watchlist","Public web source","Demo","Connector placeholder for licensed/public data.",datetime.utcnow().isoformat())])
    c.commit();c.close()
def auth(f):
    @wraps(f)
    def w(*a,**k):
        if "uid" not in session:return redirect(url_for("login"))
        return f(*a,**k)
    return w
def audit(a,d=""):
    if "uid" in session:
        c=db();c.execute("INSERT INTO audit(user_id,action,detail,created_at) VALUES(?,?,?,?)",(session["uid"],a,d,datetime.utcnow().isoformat()));c.commit();c.close()

RULES=[
(r"\b(home|house|my place|front door|garden|bedroom|back home)\b",28,"Location / property exposure","The caption may reveal a private location.","Remove location clues and identifiable property details.","HIGH"),
(r"\b(tomorrow|tonight|next week|flying|flight|airport|holiday|dubai|ibiza|abroad|away)\b",24,"Travel disclosure","The caption may reveal current or future travel.","Remove timing/location details and consider posting after travel.","HIGH"),
(r"\b(kids|children|school|daughter|son|family)\b",16,"Family exposure","Family information can increase privacy exposure.","Remove unnecessary family details and identifiable context.","MEDIUM"),
(r"\b(address|postcode|street|phone|number|email)\b",30,"Personal information","The caption appears to contain direct personal-data clues.","Remove personal contact/address information.","HIGH"),
(r"\b(routine|every morning|every night|daily|usual|regularly)\b",18,"Routine exposure","The caption may establish a predictable routine.","Remove recurring timing or routine information.","MEDIUM"),
(r"\b(password|passcode|pin|api key|secret|token)\b",45,"Credential exposure","Caption contains language associated with secrets.","Do not publish credentials or secret material.","CRITICAL")
]
def caption_scan(t):
    score=5;out=[]
    for pat,pts,cat,detail,rec,sev in RULES:
        if re.search(pat,(t or "").lower()):
            score+=pts;out.append({"category":cat,"detail":detail,"recommendation":rec,"severity":sev})
    return min(99,score),out

def image_scan(path):
    out=[]; meta={}
    try:
        im=Image.open(path); meta={"width":im.width,"height":im.height,"format":im.format}
        exif=im.getexif()
        if exif:
            meta["exif_fields"]=len(exif)
            if any(ExifTags.TAGS.get(k)=="GPSInfo" for k in exif):
                out.append({"category":"GPS metadata","detail":"GPS metadata is present and can reveal capture location.","recommendation":"Strip GPS metadata before publication.","severity":"HIGH"})
        # Lightweight visual risk heuristics that work offline.
        if im.width*im.height>30000000:
            out.append({"category":"High-resolution detail","detail":"Very high resolution may expose small identifiers.","recommendation":"Review plates, documents, screens, addresses and signage at 100% zoom.","severity":"LOW"})
        if im.width<600 or im.height<600:
            out.append({"category":"Low-resolution image","detail":"Low resolution limits automated visual inspection.","recommendation":"Perform a manual security review.","severity":"LOW"})
    except Exception:
        out.append({"category":"Image inspection","detail":"The image could not be inspected.","recommendation":"Complete a manual review before publishing.","severity":"MEDIUM"})
    if not out:out.append({"category":"Image metadata","detail":"No GPS metadata detected by this offline scanner.","recommendation":"Still review visual background and platform location tags.","severity":"LOW"})
    return out,meta

def risk(score):
    return "CRITICAL" if score>=80 else "HIGH" if score>=60 else "MODERATE" if score>=40 else "LOW"
@app.route("/register", methods=["GET", "POST"])
def register():
            c = db()
        user_exists = c.execute("SELECT id FROM users LIMIT 1").fetchone()
        c.close()
        if user_exists:
                            flash("Registration is closed.")
                            return redirect(url_for("login"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

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
            (email,)
        ).fetchone()

        if existing:
            c.close()
            flash("An account with that email already exists.")
            return render_template("register.html")

        c.execute(
            "INSERT INTO users(email,password,role,created_at) VALUES(?,?,?,?)",
            (
                email,
                generate_password_hash(password),
                "admin",
                datetime.utcnow().isoformat()
            )
        )

        c.commit()
        c.close()

        flash("Account created. You can now sign in.")
        return redirect(url_for("login"))

    return render_template("register.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        e = request.form.get("email", "").strip().lower()
        p = request.form.get("password", "")

        c = db()
        u = c.execute(
            "SELECT * FROM users WHERE email=?",
            (e,)
        ).fetchone()
        c.close()

        if u and check_password_hash(u["password"], p):
            session.clear()
            session["uid"] = u["id"]
            session["email"] = e
            return redirect("/")

        flash("Invalid credentials.")

    return render_template("login.html")
    
@app.post("/logout")
@auth
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/")
@auth
def home():
    c=db();ps=c.execute("SELECT * FROM principals ORDER BY risk DESC").fetchall()
    alerts=c.execute("SELECT a.*,p.name principal FROM alerts a LEFT JOIN principals p ON p.id=a.principal_id ORDER BY a.id DESC").fetchall()
    cases=c.execute("SELECT * FROM cases ORDER BY id DESC").fetchall();sources=c.execute("SELECT * FROM sources").fetchall()
    stats={"principals":len(ps),"alerts":sum(a["status"]=="Open" for a in alerts),"checks":c.execute("SELECT COUNT(*) n FROM checks").fetchone()["n"],"cases":sum(x["status"]=="Open" for x in cases)}
    c.close();return render_template("app.html",principals=ps,alerts=alerts,cases=cases,sources=sources,stats=stats)

@app.post("/api/scan")
@auth
def scan():
    pid=request.form.get("principal_id") or None;caption=request.form.get("caption","");score,findings=caption_scan(caption)
    f=request.files.get("image");filename=None;meta={}
    if f and f.filename:
        ext=os.path.splitext(f.filename)[1].lower()
        if ext not in [".jpg",".jpeg",".png",".webp"]:return jsonify(error="Unsupported image type"),400
        filename=secrets.token_hex(16)+ext;path=os.path.join(UP,filename);f.save(path)
        fi,meta=image_scan(path);findings+=fi;score=min(99,score+sum(20 if x["severity"] in ("HIGH","CRITICAL") else 5 for x in fi if x["category"]!="Image metadata"))
    r=risk(score);c=db();c.execute("INSERT INTO checks(principal_id,filename,score,risk,findings,created_at) VALUES(?,?,?,?,?,?)",(pid,filename,score,r,json.dumps(findings),datetime.utcnow().isoformat()));c.commit();c.close();audit("security_scan",f"{r} {score}")
    return jsonify(score=score,risk=r,findings=findings,metadata=meta)

@app.post("/api/principals")
@auth
def add_principal():
    d=request.get_json();name=(d.get("name") or "").strip();role=(d.get("role") or "Executive").strip()
    if not name:return jsonify(error="Name required"),400
    c=db();c.execute("INSERT INTO principals(name,role,created_at) VALUES(?,?,?)",(name,role,datetime.utcnow().isoformat()));c.commit();c.close();audit("add_principal",name);return jsonify(ok=True)

@app.post("/api/alerts/<int:i>/close")
@auth
def close_alert(i):
    c=db();c.execute("UPDATE alerts SET status='Closed' WHERE id=?", (i,));c.commit();c.close();audit("close_alert",str(i));return jsonify(ok=True)
@app.post("/api/cases")
@auth
def create_case():
    d=request.get_json();title=(d.get("title") or "Security case").strip();c=db();c.execute("INSERT INTO cases(title,owner,notes,created_at) VALUES(?,?,?,?)",(title,session.get("email"),d.get("notes",""),datetime.utcnow().isoformat()));c.commit();c.close();audit("create_case",title);return jsonify(ok=True)
@app.post("/api/cases/<int:i>/close")
@auth
def close_case(i):
    c=db();c.execute("UPDATE cases SET status='Closed' WHERE id=?",(i,));c.commit();c.close();audit("close_case",str(i));return jsonify(ok=True)
@app.post("/api/sources")
@auth
def add_source():
    d=request.get_json();name=(d.get("name") or "").strip();kind=(d.get("kind") or "Authorised source").strip()
    if not name:return jsonify(error="Name required"),400
    c=db();c.execute("INSERT INTO sources(name,kind,status,notes,created_at) VALUES(?,?,?,?,?)",(name,kind,"Configured","Connector must be implemented with an official/licensed API.",datetime.utcnow().isoformat()));c.commit();c.close();audit("add_source",name);return jsonify(ok=True)
@app.get("/api/audit")
@auth
def audit_api():
    c=db();r=c.execute("SELECT a.*,u.email FROM audit a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 150").fetchall();c.close();return jsonify([dict(x) for x in r])
@app.get("/health")
def health():return jsonify(status="ok",service="postguard",version="4.0")

init()

if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000"))
    )
