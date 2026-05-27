import os
import base64
import hashlib
import secrets
import json
import requests
from flask import Flask, redirect, request, session, url_for
from urllib.parse import urlencode
import jwt
from jwt import PyJWKClient
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

CLIENT_ID     = os.environ.get("TG_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("TG_CLIENT_SECRET", "")
REDIRECT_URI  = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")
DATABASE_URL  = os.environ.get("DATABASE_URL", "")

AUTH_URL  = "https://oauth.telegram.org/auth"
TOKEN_URL = "https://oauth.telegram.org/token"
JWKS_URL  = "https://oauth.telegram.org/.well-known/jwks.json"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """إنشاء جدول المستخدمين إذا لم يكن موجوداً"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          SERIAL PRIMARY KEY,
            telegram_id TEXT UNIQUE NOT NULL,
            name        TEXT,
            username    TEXT,
            phone       TEXT,
            created_at  TIMESTAMP DEFAULT NOW(),
            last_login  TIMESTAMP DEFAULT NOW()
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

def upsert_user(telegram_id, name, username, phone):
    """أضف مستخدم جديد أو حدّث بياناته إذا كان موجوداً"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        INSERT INTO users (telegram_id, name, username, phone, last_login)
        VALUES (%s, %s, %s, %s, NOW())
        ON CONFLICT (telegram_id) DO UPDATE SET
            name       = EXCLUDED.name,
            username   = EXCLUDED.username,
            phone      = EXCLUDED.phone,
            last_login = NOW()
        RETURNING *
    """, (telegram_id, name, username, phone))
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return user

def get_all_users():
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users ORDER BY last_login DESC")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return users

# ── PKCE ─────────────────────────────────────────────────────────────────────
def generate_code_verifier():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    user = session.get("user")
    if user:
        return f"""
        <h2>✅ مرحباً {user.get('name', 'مجهول')}!</h2>
        <ul>
          <li><b>Telegram ID:</b> {user.get('sub')}</li>
          <li><b>Username:</b> @{user.get('preferred_username', 'N/A')}</li>
          <li><b>Phone:</b> {user.get('phone_number', 'لم يُشارَك')}</li>
        </ul>
        <a href="/users">📋 عرض كل المستخدمين</a> |
        <a href="/logout">تسجيل الخروج</a>
        """
    return """
    <h2>Telegram Login</h2>
    <a href="/login">
      <img src="https://telegram.org/img/t_logo.png" width=24>
      تسجيل الدخول عبر Telegram
    </a>
    """

@app.route("/login")
def login():
    code_verifier  = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state          = secrets.token_urlsafe(16)
    session["code_verifier"] = code_verifier
    session["state"]         = state

    params = {
        "client_id":             CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "response_type":         "code",
        "scope":                 "openid profile phone",
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    }
    return redirect(AUTH_URL + "?" + urlencode(params))

@app.route("/callback")
def callback():
    if request.args.get("state") != session.get("state"):
        return "❌ state mismatch", 400

    code = request.args.get("code")
    if not code:
        return f"❌ لم يُمنح التفويض: {request.args.get('error', 'unknown')}", 400

    credentials = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    token_resp = requests.post(
        TOKEN_URL,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type":  "application/x-www-form-urlencoded",
        },
        data={
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  REDIRECT_URI,
            "client_id":     CLIENT_ID,
            "code_verifier": session.get("code_verifier", ""),
        },
        timeout=10,
    )

    if not token_resp.ok:
        return f"❌ فشل token exchange: {token_resp.text}", 400

    id_token = token_resp.json().get("id_token")

    try:
        jwks_client = PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=str(CLIENT_ID),
            issuer="https://oauth.telegram.org",
        )
    except Exception as e:
        return f"❌ فشل التحقق من JWT: {e}", 400

    # ── حفظ في PostgreSQL ──
    upsert_user(
        telegram_id = str(payload.get("sub")),
        name        = payload.get("name"),
        username    = payload.get("preferred_username"),
        phone       = payload.get("phone_number"),
    )

    session["user"] = payload
    return redirect(url_for("index"))

@app.route("/users")
def users():
    """صفحة عرض كل المستخدمين المسجلين"""
    if not session.get("user"):
        return redirect(url_for("index"))
    rows = get_all_users()
    html = "<h2>📋 المستخدمون المسجلون</h2><table border=1 cellpadding=8>"
    html += "<tr><th>ID</th><th>Telegram ID</th><th>الاسم</th><th>Username</th><th>الهاتف</th><th>آخر دخول</th></tr>"
    for r in rows:
        html += f"<tr><td>{r['id']}</td><td>{r['telegram_id']}</td><td>{r['name']}</td><td>@{r['username']}</td><td>{r['phone']}</td><td>{r['last_login']}</td></tr>"
    html += "</table><br><a href='/'>رجوع</a>"
    return html

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    if DATABASE_URL:
        init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
