"""QR Medic - Emergency Student Medical Profile System (Flask + MySQL backend), v2."""
import os, json, base64, secrets, smtplib, socket, threading, urllib.parse, urllib.request
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from flask import Flask, Response, jsonify, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import pymysql, pymysql.cursors

E = os.getenv
# ---------- EDIT THESE (or set environment variables when deploying) ----------
DB_HOST, DB_PORT = E("DB_HOST", "localhost"), int(E("DB_PORT", "3306"))
DB_USER, DB_PASSWORD = E("DB_USER", "root"), E("DB_PASSWORD", "your_mysql_password")
DB_NAME = E("DB_NAME", "qr_medic_app")
PORT = int(E("PORT", "5000"))
PUBLIC_URL = E("PUBLIC_URL", "").rstrip("/")          # e.g. https://qrmedic.onrender.com
# Optional services - leave empty and the app prints what it WOULD send (demo mode)
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS = E("SMTP_HOST", ""), int(E("SMTP_PORT", "587")), E("SMTP_USER", ""), E("SMTP_PASS", "")
MAIL_FROM = E("MAIL_FROM", SMTP_USER)
BREVO_API_KEY = E("BREVO_API_KEY", "")   # email over HTTPS - works on free Render (SMTP is blocked there)
TWILIO_SID, TWILIO_TOKEN = E("TWILIO_SID", ""), E("TWILIO_TOKEN", "")
TWILIO_SMS_FROM, TWILIO_WA_FROM = E("TWILIO_SMS_FROM", ""), E("TWILIO_WA_FROM", "")   # e.g. +1415...
COUNTRY_CODE = E("COUNTRY_CODE", "+91")
ANTHROPIC_API_KEY, AI_MODEL = E("ANTHROPIC_API_KEY", ""), E("AI_MODEL", "claude-sonnet-5-5")
# -------------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = E("SECRET_KEY", "change-this-secret-key")
app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=PUBLIC_URL.startswith("https"))

TEXT = ["name", "roll", "course", "phone", "dob", "addr", "blood", "allergies", "cond", "meds", "doc", "ecn", "ecp", "ecr"]
SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users(
      id VARCHAR(20) PRIMARY KEY, role VARCHAR(10) NOT NULL DEFAULT 'student',
      email VARCHAR(160) NOT NULL UNIQUE, pass_hash VARCHAR(255) NOT NULL,
      name VARCHAR(120), roll VARCHAR(60), course VARCHAR(80), phone VARCHAR(30), dob VARCHAR(20), addr VARCHAR(255),
      blood VARCHAR(5), allergies TEXT, cond TEXT, meds TEXT, doc VARCHAR(160),
      ecn VARCHAR(120), ecp VARCHAR(30), ecr VARCHAR(60), active TINYINT(1) NOT NULL DEFAULT 1,
      photo LONGTEXT, expires_on DATE NULL, reset_token VARCHAR(80), reset_exp DATETIME NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP) CHARACTER SET utf8mb4""",
    """CREATE TABLE IF NOT EXISTS scans(
      id INT AUTO_INCREMENT PRIMARY KEY, uid VARCHAR(20) NOT NULL, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      by_who VARCHAR(120), loc VARCHAR(60), ok TINYINT(1), INDEX(uid)) CHARACTER SET utf8mb4""",
    """CREATE TABLE IF NOT EXISTS audit(
      id INT AUTO_INCREMENT PRIMARY KEY, at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      user_email VARCHAR(160), action VARCHAR(255)) CHARACTER SET utf8mb4""",
    """CREATE TABLE IF NOT EXISTS vaccinations(
      id INT AUTO_INCREMENT PRIMARY KEY, uid VARCHAR(20) NOT NULL, name VARCHAR(120), taken_on VARCHAR(20),
      FOREIGN KEY (uid) REFERENCES users(id) ON DELETE CASCADE) CHARACTER SET utf8mb4""",
    """CREATE TABLE IF NOT EXISTS reports(
      id INT AUTO_INCREMENT PRIMARY KEY, uid VARCHAR(20) NOT NULL, name VARCHAR(200), data LONGTEXT,
      uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (uid) REFERENCES users(id) ON DELETE CASCADE) CHARACTER SET utf8mb4""",
    """CREATE TABLE IF NOT EXISTS reminders(
      id INT AUTO_INCREMENT PRIMARY KEY, uid VARCHAR(20) NOT NULL, name VARCHAR(160), at_time VARCHAR(10),
      FOREIGN KEY (uid) REFERENCES users(id) ON DELETE CASCADE) CHARACTER SET utf8mb4""",
]
MIGRATE = ["ALTER TABLE users ADD COLUMN photo LONGTEXT", "ALTER TABLE users ADD COLUMN expires_on DATE NULL",
           "ALTER TABLE users ADD COLUMN reset_token VARCHAR(80)", "ALTER TABLE users ADD COLUMN reset_exp DATETIME NULL"]

# ---------- database helpers ----------
def conn(db=True):
    kw = dict(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME if db else None,
              charset="utf8mb4", autocommit=True, cursorclass=pymysql.cursors.DictCursor)
    if E("DB_SSL_CA"): kw["ssl_ca"] = E("DB_SSL_CA")
    return pymysql.connect(**kw)

def q(sql, args=(), one=False, last=False):
    c = conn()
    try:
        with c.cursor() as cur:
            cur.execute(sql, args)
            return cur.lastrowid if last else (cur.fetchone() if one else cur.fetchall())
    finally:
        c.close()

def init_db():
    try:                                   # cloud databases already exist and may block CREATE DATABASE
        c = conn(False)
        with c.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4")
        c.close()
    except Exception as e:
        print("[note] skipped CREATE DATABASE:", e)
    for s in SCHEMA: q(s)
    for m in MIGRATE:                      # upgrade an older v1 database
        try: q(m)
        except pymysql.err.OperationalError: pass
    if not q("SELECT id FROM users WHERE role='admin'", one=True):
        q("INSERT INTO users(id,role,email,pass_hash,name) VALUES('ADMIN','admin',%s,%s,'System Admin')",
          ("admin@qrmedic.com", generate_password_hash("admin123")))

# ---------- notifications (email / SMS / WhatsApp) ----------
def bg(fn, *a): threading.Thread(target=fn, args=a, daemon=True).start()

def send_mail(to, subject, body):
    if not to: return
    if BREVO_API_KEY:
        try:
            req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", data=json.dumps(
                {"sender": {"name": "QR Medic", "email": MAIL_FROM}, "to": [{"email": to}], "subject": subject, "textContent": body}).encode(),
                headers={"api-key": BREVO_API_KEY, "content-type": "application/json", "accept": "application/json"})
            urllib.request.urlopen(req, timeout=15)
        except Exception as e:
            print("[Brevo error]", getattr(e, "read", lambda: e)())
        return
    if not SMTP_HOST:
        print(f"\n[EMAIL demo - set SMTP_* to really send] to={to}\n  {subject}\n  {body}\n"); return
    try:
        m = EmailMessage(); m["From"], m["To"], m["Subject"] = MAIL_FROM or SMTP_USER, to, subject; m.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.send_message(m)
    except Exception as e: print("[EMAIL error]", e)

def phone(n):
    n = "".join(c for c in (n or "") if c.isdigit() or c == "+")
    return "" if not n else (n if n.startswith("+") else COUNTRY_CODE + n.lstrip("0"))

def notify_guardian(to, body):
    to = phone(to)
    if not to: return
    if not (TWILIO_SID and TWILIO_TOKEN):
        print(f"\n[SMS/WhatsApp demo - set TWILIO_* to really send] to={to}\n  {body}\n"); return
    for frm, pre in ((TWILIO_SMS_FROM, ""), (TWILIO_WA_FROM, "whatsapp:")):
        if not frm: continue
        data = urllib.parse.urlencode({"To": pre + to, "From": pre + frm, "Body": body}).encode()
        req = urllib.request.Request(f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json", data=data)
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{TWILIO_SID}:{TWILIO_TOKEN}".encode()).decode())
        try: urllib.request.urlopen(req, timeout=15)
        except Exception as e: print("[Twilio error]", e)

def alert_owner(u, by, st):
    t = datetime.now().strftime("%d %b %H:%M")
    send_mail(u["email"], "Your QR Medic code was scanned",
              f"Hello {u['name']},\n\nYour emergency QR was scanned on {t} ({by}). Status: {st}.\nLog in to see your scan history.\n")
    if st == "ok" and u["ecp"]:
        notify_guardian(u["ecp"], f"QR Medic ALERT: {u['name']}'s emergency QR was just scanned ({t}). Please stay reachable.")

# ---------- AI emergency summary ----------
def facts_of(u):
    vac = [v["name"] for v in q("SELECT name FROM vaccinations WHERE uid=%s", (u["id"],))]
    return {"name": u["name"], "blood_group": u["blood"] or "unknown", "allergies": u["allergies"] or "none reported",
            "conditions": u["cond"] or "none reported", "medicines": u["meds"] or "none", "vaccinations": vac,
            "guardian": f"{u['ecn'] or '-'} {u['ecp'] or ''}".strip()}

def ai_summary(u):
    f = facts_of(u)
    base = "\n".join([f"{f['name']} - blood group {f['blood_group']}.",
                      f"ALLERGIES: {f['allergies']}. Avoid related drugs and foods.", f"Conditions: {f['conditions']}.",
                      f"Medicines: {f['medicines']}.", f"Call guardian: {f['guardian']}.",
                      "Check breathing and consciousness, then call local emergency services."])
    if not ANTHROPIC_API_KEY: return base
    try:
        body = json.dumps({"model": AI_MODEL, "max_tokens": 300, "messages": [{"role": "user", "content":
            "You help paramedics. From these student medical facts write a calm brief of at most 6 short lines: most critical "
            "items first (allergies, conditions, medicines, blood group), then who to call. Do not diagnose and do not invent "
            "anything that is not listed.\n" + json.dumps(f)}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "content-type": "application/json", "x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"})
        r = json.loads(urllib.request.urlopen(req, timeout=25).read())
        return "".join(b.get("text", "") for b in r["content"] if b.get("type") == "text").strip() or base
    except Exception as e:
        print("[AI error]", e); return base

# ---------- user helpers ----------
def items(uid):
    return ([{"id": r["id"], "n": r["name"], "d": r["taken_on"]} for r in q("SELECT * FROM vaccinations WHERE uid=%s ORDER BY id", (uid,))],
            [{"id": r["id"], "n": r["name"], "t": str(r["uploaded_at"])} for r in q("SELECT id,name,uploaded_at FROM reports WHERE uid=%s ORDER BY id", (uid,))],
            [{"id": r["id"], "n": r["name"], "t": r["at_time"]} for r in q("SELECT * FROM reminders WHERE uid=%s ORDER BY at_time", (uid,))])

def qr_state(u):
    if not u["active"]: return "off"
    if u.get("expires_on") and date.today() > u["expires_on"]: return "expired"
    return "ok"

def user_dict(u, full=True):
    d = {k: (u.get(k) or "") for k in TEXT}
    d.update(id=u["id"], role=u["role"], email=u["email"], active=bool(u["active"]), state=qr_state(u),
             expires=str(u["expires_on"]) if u.get("expires_on") else "", photo=(u.get("photo") or "") if full else "")
    d["vacc"], d["rep"], d["rem"] = items(u["id"]) if full else ([], [], [])
    return d

def current():
    uid = session.get("uid")
    return q("SELECT * FROM users WHERE id=%s", (uid,), True) if uid else None

def audit(action, email=None):
    if email is None:
        u = current(); email = u["email"] if u else "guest"
    q("INSERT INTO audit(user_email,action) VALUES(%s,%s)", (email, action[:255]))

def err(msg, code=400): return jsonify(error=msg), code
def base_url(): return PUBLIC_URL or request.host_url.rstrip("/")

# ---------- pages ----------
@app.route("/")
@app.route("/e/<path:_>")
def index(_=None): return send_from_directory(HERE, "index.html")

# ---------- auth ----------
@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    email, pw, name = (d.get("email") or "").strip().lower(), (d.get("pass") or "").strip(), (d.get("name") or "").strip()
    if not name or "@" not in email or len(pw) < 6: return err("Enter a name, valid email and a password of 6+ characters")
    if q("SELECT id FROM users WHERE email=%s", (email,), True): return err("That email is already registered - log in instead", 409)
    uid = "S" + secrets.token_hex(3).upper()
    q("INSERT INTO users(id,role,email,pass_hash,name,roll,course) VALUES(%s,'student',%s,%s,%s,%s,%s)",
      (uid, email, generate_password_hash(pw), name, (d.get("roll") or "")[:60], (d.get("course") or "")[:80]))
    session["uid"] = uid
    audit("Registered account", email)
    bg(send_mail, email, "Welcome to QR Medic", f"Hello {name},\n\nYour account is ready. Complete your medical profile and download your QR code.\nYour scanner ID is {uid}.\n")
    return jsonify(user_dict(current()))

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    email, pw = (d.get("email") or "").strip().lower(), (d.get("pass") or "").strip()
    u = q("SELECT * FROM users WHERE email=%s", (email,), True)
    if not u or not check_password_hash(u["pass_hash"], pw):
        audit("Failed login for " + email, "guest"); return err("Email or password is incorrect", 401)
    session["uid"] = u["id"]; audit("Logged in", email)
    return jsonify(user_dict(u))

@app.post("/api/logout")
def logout():
    audit("Logged out"); session.clear(); return jsonify(ok=True)

@app.post("/api/password")
def change_password():
    u = current()
    if not u: return err("Please log in", 401)
    d = request.get_json(force=True); new = (d.get("new") or "").strip()
    if not check_password_hash(u["pass_hash"], (d.get("old") or "").strip()): return err("Current password is wrong", 403)
    if len(new) < 6: return err("New password must be 6+ characters")
    q("UPDATE users SET pass_hash=%s WHERE id=%s", (generate_password_hash(new), u["id"]))
    audit("Changed password"); bg(send_mail, u["email"], "Your QR Medic password was changed", "If this was not you, reset your password immediately.")
    return jsonify(ok=True)

@app.post("/api/forgot")
def forgot():
    email = ((request.get_json(force=True) or {}).get("email") or "").strip().lower()
    u = q("SELECT * FROM users WHERE email=%s", (email,), True)
    if u:
        tok = secrets.token_urlsafe(24)
        q("UPDATE users SET reset_token=%s, reset_exp=%s WHERE id=%s", (tok, datetime.now() + timedelta(minutes=30), u["id"]))
        audit("Requested password reset", email)
        bg(send_mail, email, "Reset your QR Medic password", f"Open this link within 30 minutes to set a new password:\n{base_url()}/?reset={tok}\n")
    return jsonify(msg="If that email is registered, a reset link has been sent. (Demo mode: check the server window.)")

@app.post("/api/reset")
def reset():
    d = request.get_json(force=True); pw = (d.get("pass") or "").strip()
    u = q("SELECT * FROM users WHERE reset_token=%s AND reset_exp>%s", (d.get("token") or "-", datetime.now()), True)
    if not u: return err("This reset link is invalid or has expired", 400)
    if len(pw) < 6: return err("Password must be 6+ characters")
    q("UPDATE users SET pass_hash=%s, reset_token=NULL, reset_exp=NULL WHERE id=%s", (generate_password_hash(pw), u["id"]))
    audit("Password reset completed", u["email"]); return jsonify(ok=True)

@app.get("/api/config")
def config():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("10.255.255.255", 1)); ip = s.getsockname()[0]
    except Exception: ip = "127.0.0.1"
    finally: s.close()
    return jsonify(lan=f"http://{ip}:{PORT}")

# ---------- profile ----------
@app.get("/api/me")
def me_get():
    u = current()
    return jsonify(user_dict(u)) if u else err("Please log in", 401)

@app.put("/api/me")
def me_put():
    u = current()
    if not u: return err("Please log in", 401)
    d = request.get_json(force=True); sets, vals = [], []
    for k in TEXT:
        if k in d: sets.append(f"{k}=%s"); vals.append(str(d[k] or "")[:1000])
    if "photo" in d and len(d["photo"] or "") < 300000: sets.append("photo=%s"); vals.append(d["photo"] or "")
    if "expires" in d:
        try: ex = datetime.strptime(d["expires"], "%Y-%m-%d").date() if d["expires"] else None
        except ValueError: return err("Invalid date")
        sets.append("expires_on=%s"); vals.append(ex)
    if sets: q(f"UPDATE users SET {','.join(sets)} WHERE id=%s", (*vals, u["id"]))
    return jsonify(user_dict(current()))

@app.post("/api/users/<uid>/toggle")
def toggle(uid):
    u = current()
    if not u: return err("Please log in", 401)
    if u["role"] != "admin" and u["id"] != uid: return err("Not allowed", 403)
    t = q("SELECT * FROM users WHERE id=%s", (uid,), True)
    if not t: return err("Not found", 404)
    new = 0 if t["active"] else 1
    q("UPDATE users SET active=%s WHERE id=%s", (new, uid))
    audit(("Activated" if new else "Deactivated") + " QR of " + t["email"]); return jsonify(active=bool(new))

@app.post("/api/log")
def log_action():
    if current(): audit(str((request.get_json(force=True) or {}).get("a", ""))[:255])
    return jsonify(ok=True)

# ---------- vaccinations / reports / reminders (own tables) ----------
KIND = {"vacc": ("vaccinations", "name,taken_on", lambda d: (d.get("n", "")[:120], d.get("d", "")[:20]), 0),
        "rem": ("reminders", "name,at_time", lambda d: (d.get("n", "")[:160], d.get("t", "")[:10]), 2),
        "rep": ("reports", "name,data", lambda d: (d.get("n", "")[:200], d.get("d", "")), 1)}

@app.post("/api/items/<kind>")
def item_add(kind):
    u = current()
    if not u or kind not in KIND: return err("Please log in", 401)
    tbl, cols, fn, idx = KIND[kind]; vals = fn(request.get_json(force=True))
    if not vals[0]: return err("Name is required")
    if kind == "rep" and not (vals[1].startswith("data:") and len(vals[1]) < 600000): return err("File must be under 400 KB")
    q(f"INSERT INTO {tbl}(uid,{cols}) VALUES(%s,%s,%s)", (u["id"], *vals)); audit("Added to " + tbl)
    return jsonify(items(u["id"])[idx])

@app.delete("/api/items/<kind>/<int:iid>")
def item_del(kind, iid):
    u = current()
    if not u or kind not in KIND: return err("Please log in", 401)
    tbl, _, _, idx = KIND[kind]
    q(f"DELETE FROM {tbl} WHERE id=%s AND uid=%s", (iid, u["id"])); audit("Removed from " + tbl)
    return jsonify(items(u["id"])[idx])

@app.get("/api/reports/<int:rid>")
def report_get(rid):
    u = current()
    if not u: return err("Please log in", 401)
    r = q("SELECT * FROM reports WHERE id=%s", (rid,), True)
    if not r or (u["role"] != "admin" and r["uid"] != u["id"]): return err("Not found", 404)
    head, _, b64 = r["data"].partition(",")
    return Response(base64.b64decode(b64), mimetype=head[5:].split(";")[0] or "application/octet-stream",
                    headers={"Content-Disposition": f'inline; filename="{r["name"]}"'})

# ---------- admin / history ----------
@app.get("/api/users")
def users():
    u = current()
    if not u or u["role"] != "admin": return err("Admins only", 403)
    return jsonify([user_dict(x, False) for x in q("SELECT * FROM users ORDER BY created_at DESC")])

@app.get("/api/audit")
def audit_list():
    u = current()
    if not u or u["role"] != "admin": return err("Admins only", 403)
    return jsonify([{"t": str(r["at"]), "u": r["user_email"], "a": r["action"]} for r in q("SELECT at,user_email,action FROM audit ORDER BY id DESC LIMIT 300")])

@app.get("/api/scans")
def scans():
    u = current()
    if not u: return err("Please log in", 401)
    sql = "SELECT s.uid,s.scanned_at,s.by_who,s.loc,s.ok,u.name FROM scans s JOIN users u ON u.id=s.uid "
    rows = q(sql + "ORDER BY s.id DESC LIMIT 200") if u["role"] == "admin" else q(sql + "WHERE s.uid=%s ORDER BY s.id DESC LIMIT 200", (u["id"],))
    return jsonify([{"uid": r["uid"], "t": str(r["scanned_at"]), "by": r["by_who"], "loc": r["loc"] or "", "ok": bool(r["ok"]), "name": r["name"]} for r in rows])

@app.get("/api/summary")
def my_summary():
    u = current()
    return jsonify(text=ai_summary(u)) if u else err("Please log in", 401)

# ---------- PUBLIC: what a QR scan opens ----------
@app.get("/api/e/<sid>")
def emergency(sid):
    u = q("SELECT * FROM users WHERE id=%s AND role='student'", (sid.upper(),), True)
    if not u: return err("Profile not found", 404)
    by, st = (request.args.get("by") or "Phone camera scan")[:100], qr_state(u)
    scan = q("INSERT INTO scans(uid,by_who,loc,ok) VALUES(%s,%s,%s,%s)", (u["id"], by, "", st == "ok"), last=True)
    audit("QR scanned (" + by + ")", u["email"])
    if by != "Preview": bg(alert_owner, u, by, st)
    if st != "ok": return jsonify(active=False, reason=st, name=u["name"])
    d = {k: u[k] or "" for k in ["name", "course", "roll", "blood", "allergies", "cond", "meds", "doc", "ecn", "ecp", "ecr"]}
    d.update(id=u["id"], active=True, scan=scan, photo=u["photo"] or "", vacc=[{"n": v["name"]} for v in q("SELECT name FROM vaccinations WHERE uid=%s", (u["id"],))])
    return jsonify(d)

@app.get("/api/e/<sid>/summary")
def public_summary(sid):
    u = q("SELECT * FROM users WHERE id=%s AND role='student'", (sid.upper(),), True)
    if not u or qr_state(u) != "ok": return err("Not available", 404)
    return jsonify(text=ai_summary(u))

@app.post("/api/e/<sid>/location")
def scan_location(sid):
    d = request.get_json(force=True)
    try: lat, lng, scan = float(d["lat"]), float(d["lng"]), int(d["scan"])
    except (KeyError, ValueError, TypeError): return err("Bad location")
    u = q("SELECT * FROM users WHERE id=%s", (sid.upper(),), True)
    s = q("SELECT id FROM scans WHERE id=%s AND uid=%s AND (loc IS NULL OR loc='') AND scanned_at > %s", (scan, sid.upper(), datetime.now() - timedelta(hours=1)), True)
    if not (u and s): return err("Not allowed", 403)
    loc = f"{lat:.5f},{lng:.5f}"
    q("UPDATE scans SET loc=%s WHERE id=%s", (loc, scan))
    bg(notify_guardian, u["ecp"], f"QR Medic: live location of the person who scanned {u['name']}'s QR: https://maps.google.com/?q={loc}")
    return jsonify(ok=True)

init_db()   # also runs under gunicorn when deployed

if __name__ == "__main__":
    with app.app_context(): lan = config().get_json()["lan"]
    print(f"\n QR Medic is running.\n  On this computer : http://localhost:{PORT}\n  On your phone    : {lan}  (same Wi-Fi)\n  Admin login      : admin@qrmedic.com / admin123\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
