import os,re,json,secrets,sqlite3
from datetime import datetime,timezone
from functools import wraps
from flask import Flask,render_template,request,redirect,url_for,session,jsonify,flash,abort
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image

BASE=os.path.dirname(__file__); DATA=os.path.join(BASE,"data"); UP=os.path.join(DATA,"uploads")
os.makedirs(UP,exist_ok=True); DB=os.path.join(DATA,"postguard.db")
app=Flask(__name__); app.secret_key=os.getenv("POSTGUARD_SECRET","CHANGE-ME")
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE","0")=="1",
                  MAX_CONTENT_LENGTH=10*1024*1024)
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def now():return datetime.now(timezone.utc).isoformat()
def init():
 c=db();c.executescript("""CREATE TABLE IF NOT EXISTS organisations(id INTEGER PRIMARY KEY,name TEXT UNIQUE,created_at TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,org_id INTEGER,email TEXT UNIQUE,password TEXT,role TEXT,mfa_enabled INTEGER DEFAULT 0,created_at TEXT);
CREATE TABLE IF NOT EXISTS principals(id INTEGER PRIMARY KEY,org_id INTEGER,name TEXT,role TEXT,risk INTEGER DEFAULT 0,created_at TEXT);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,org_id INTEGER,principal_id INTEGER,filename TEXT,score INTEGER,risk TEXT,findings TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,org_id INTEGER,principal_id INTEGER,severity TEXT,category TEXT,detail TEXT,recommendation TEXT,status TEXT DEFAULT 'Open',created_at TEXT);
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,org_id INTEGER,title TEXT,status TEXT DEFAULT 'Open',owner TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,org_id INTEGER,user_id INTEGER,action TEXT,detail TEXT,created_at TEXT);""")
 if not c.execute("SELECT 1 FROM organisations").fetchone():
  c.execute("INSERT INTO organisations(name,created_at) VALUES(?,?)",("Demo Organisation",now()));oid=c.execute("SELECT id FROM organisations WHERE name='Demo Organisation'").fetchone()[0]
  c.execute("INSERT INTO users(org_id,email,password,role,created_at) VALUES(?,?,?,?,?)",(oid,"demo@postguard.local",generate_password_hash("ChangeMe123!"),"owner",now()))
  c.executemany("INSERT INTO principals(org_id,name,role,risk,created_at) VALUES(?,?,?,?,?)",[(oid,"Alex Morgan","Professional Footballer",63,now()),(oid,"Jordan Lee","Executive",41,now())])
 c.commit();c.close()
RULES=[(r"\b(home|house|front door|garden|bedroom)\b",28,"Location/property","Remove location clues.","HIGH"),(r"\b(tomorrow|tonight|flying|flight|airport|holiday|abroad|away)\b",24,"Travel disclosure","Remove timing/location details.","HIGH"),(r"\b(kids|children|school|daughter|son|family)\b",16,"Family exposure","Remove unnecessary family details.","MEDIUM"),(r"\b(address|postcode|street|phone|email)\b",30,"Personal information","Remove contact/address information.","HIGH"),(r"\b(routine|every morning|every night|daily|regularly)\b",18,"Routine exposure","Remove predictable routine details.","MEDIUM"),(r"\b(password|passcode|pin|api key|secret|token)\b",45,"Credential exposure","Never publish secrets.","CRITICAL")]
def current():
 if "uid" not in session:return None
 c=db();u=c.execute("SELECT * FROM users WHERE id=?",(session["uid"],)).fetchone();c.close();return u
def audit(a,d=""):
 u=current()
 if u:
  c=db();c.execute("INSERT INTO audit(org_id,user_id,action,detail,created_at) VALUES(?,?,?,?,?)",(u["org_id"],u["id"],a,d,now()));c.commit();c.close()
def auth(f):
 @wraps(f)
 def w(*a,**k):
  if not current():return redirect(url_for("login",next=request.path))
  return f(*a,**k)
 return w
@app.after_request
def hdr(r):
 r.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store"});return r
@app.route("/login",methods=["GET","POST"])
def login():
 if request.method=="POST":
  e=request.form.get("email","").strip().lower();p=request.form.get("password","");c=db();u=c.execute("SELECT * FROM users WHERE email=?",(e,)).fetchone();c.close()
  if u and check_password_hash(u["password"],p):
   session.clear();session["uid"]=u["id"];audit("login",e);return redirect(request.args.get("next") or "/")
  flash("Invalid email or password.")
 return render_template("login.html")
@app.get("/logout")
def logout():audit("logout");session.clear();return redirect(url_for("login"))
@app.get("/")
@auth
def home():
 u=current();c=db();ps=c.execute("SELECT * FROM principals WHERE org_id=? ORDER BY risk DESC",(u["org_id"],)).fetchall();aa=c.execute("SELECT a.*,p.name principal FROM alerts a LEFT JOIN principals p ON p.id=a.principal_id WHERE a.org_id=? ORDER BY a.id DESC",(u["org_id"],)).fetchall();cc=c.execute("SELECT * FROM cases WHERE org_id=? ORDER BY id DESC",(u["org_id"],)).fetchall();stats={"principals":len(ps),"alerts":sum(x["status"]=="Open" for x in aa),"scans":c.execute("SELECT COUNT(*) n FROM scans WHERE org_id=?",(u["org_id"],)).fetchone()["n"],"cases":sum(x["status"]=="Open" for x in cc)};c.close();return render_template("app.html",user=u,principals=ps,alerts=aa,cases=cc,stats=stats)
@app.post("/api/scan")
@auth
def scan():
 u=current();t=request.form.get("caption","");score=5;find=[]
 for pat,pts,cat,rec,sev in RULES:
  if re.search(pat,t.lower()):score+=pts;find.append({"category":cat,"detail":"Caption contains a potential security exposure.","recommendation":rec,"severity":sev})
 f=request.files.get("image")
 if f and f.filename:
  ext=secure_filename(f.filename).rsplit(".",1)[-1].lower() if "." in f.filename else ""
  if ext not in {"jpg","jpeg","png","webp"}:return jsonify(error="Unsupported image type"),400
  name=secrets.token_hex(16)+"."+ext;path=os.path.join(UP,name);f.save(path)
  try:
   im=Image.open(path)
   if im.getexif():score+=12;find.append({"category":"Image metadata","detail":"Embedded metadata is present.","recommendation":"Strip unnecessary metadata before publication.","severity":"MEDIUM"})
   if im.width*im.height>30000000:score+=4;find.append({"category":"High-resolution detail","detail":"High resolution may expose small identifiers.","recommendation":"Review plates, documents and screens.","severity":"LOW"})
  except: find.append({"category":"Image inspection","detail":"Image could not be fully inspected.","recommendation":"Perform manual review.","severity":"MEDIUM"})
 score=min(99,score);rr="CRITICAL" if score>=80 else "HIGH" if score>=60 else "MODERATE" if score>=40 else "LOW";pid=request.form.get("principal_id") or None
 c=db();c.execute("INSERT INTO scans(org_id,principal_id,filename,score,risk,findings,created_at) VALUES(?,?,?,?,?,?,?)",(u["org_id"],pid,name if f and f.filename else None,score,rr,json.dumps(find),now()))
 for x in find:
  if x["severity"] in ("HIGH","CRITICAL"):c.execute("INSERT INTO alerts(org_id,principal_id,severity,category,detail,recommendation,created_at) VALUES(?,?,?,?,?,?,?)",(u["org_id"],pid,x["severity"],x["category"],x["detail"],x["recommendation"],now()))
 c.commit();c.close();audit("post_scan",f"{rr} {score}");return jsonify(score=score,risk=rr,findings=find)
@app.post("/api/principals")
@auth
def principal():
 u=current();d=request.get_json() or {};n=(d.get("name") or "").strip()
 if not n:return jsonify(error="Name required"),400
 c=db();c.execute("INSERT INTO principals(org_id,name,role,created_at) VALUES(?,?,?,?)",(u["org_id"],n,d.get("role","Executive"),now()));c.commit();c.close();audit("add_principal",n);return jsonify(ok=True)
@app.post("/api/alerts/<int:i>/close")
@auth
def close_alert(i):
 u=current();c=db();c.execute("UPDATE alerts SET status='Closed' WHERE id=? AND org_id=?",(i,u["org_id"]));c.commit();c.close();audit("close_alert",str(i));return jsonify(ok=True)
@app.post("/api/cases")
@auth
def case():
 u=current();d=request.get_json() or {};c=db();c.execute("INSERT INTO cases(org_id,title,owner,created_at) VALUES(?,?,?,?)",(u["org_id"],d.get("title","Security case"),u["email"],now()));c.commit();c.close();audit("create_case",d.get("title","Security case"));return jsonify(ok=True)
@app.get("/api/audit")
@auth
def audits():
 u=current();c=db();r=c.execute("SELECT a.*,u.email FROM audit a JOIN users u ON u.id=a.user_id WHERE a.org_id=? ORDER BY a.id DESC LIMIT 200",(u["org_id"],)).fetchall();c.close();return jsonify([dict(x) for x in r])
@app.get("/health")
def health():return jsonify(status="ok")
if __name__=="__main__":init();app.run(host=os.getenv("HOST","127.0.0.1"),port=int(os.getenv("PORT","5000")))
