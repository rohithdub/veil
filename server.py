"""
VEIL Backend — server.py
=========================
Handles: URL scans, AI requests, Database, Auth, Reports, History, API Security

Run:
    pip install flask flask-cors flask-limiter requests PyJWT cryptography
    python server.py

Environment (.env or shell exports):
    VEIL_SECRET_KEY    — JWT signing secret (auto-generated if absent)
    VEIL_AI_URL        — AI endpoint (default: Anthropic)
    VEIL_AI_KEY        — AI API key
    VEIL_AI_MODEL      — model name
    VEIL_AI_FORMAT     — anthropic | openai
    PORT               — listen port (default: 5000)
"""

import os, json, sqlite3, hashlib, hmac, secrets, time, re
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

import jwt
import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─── CONFIG ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "veil.db"
ENV_FILE   = BASE_DIR / ".env"

def load_env():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()

SECRET_KEY    = os.environ.get("VEIL_SECRET_KEY") or secrets.token_hex(32)
AI_URL        = os.environ.get("VEIL_AI_URL",    "https://api.anthropic.com/v1/messages")
AI_KEY        = os.environ.get("VEIL_AI_KEY",    "")
AI_MODEL      = os.environ.get("VEIL_AI_MODEL",  "claude-sonnet-4-20250514")
AI_FORMAT     = os.environ.get("VEIL_AI_FORMAT", "anthropic")   # anthropic | openai
PORT          = int(os.environ.get("PORT", 5000))
TOKEN_TTL     = int(os.environ.get("TOKEN_TTL_HOURS", 24))
ADMIN_USER    = os.environ.get("VEIL_ADMIN_USER", "admin")
ADMIN_PASS    = os.environ.get("VEIL_ADMIN_PASS", "veil-change-me")

# ─── APP ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-API-Key"])

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour", "30 per minute"],
    storage_uri="memory://"
)

# ─── DATABASE ──────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    email       TEXT UNIQUE,
    password    TEXT NOT NULL,
    api_key     TEXT UNIQUE,
    role        TEXT DEFAULT 'user',
    created_at  TEXT DEFAULT (datetime('now')),
    last_login  TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    url         TEXT NOT NULL,
    trust_score INTEGER,
    level       TEXT,
    result      TEXT,
    ip          TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    url         TEXT NOT NULL,
    type        TEXT NOT NULL,
    details     TEXT,
    status      TEXT DEFAULT 'pending',
    ip          TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    name        TEXT,
    scopes      TEXT DEFAULT 'scan,history',
    last_used   TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS rate_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT,
    endpoint    TEXT,
    ts          INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scan_user ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_url  ON scan_history(url);
CREATE INDEX IF NOT EXISTS idx_reports_url ON reports(url);
CREATE INDEX IF NOT EXISTS idx_rate_log_ip ON rate_log(ip, ts);
"""

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    # seed admin user
    uid   = secrets.token_hex(8)
    hpw   = _hash_password(ADMIN_PASS)
    akey  = "veil_" + secrets.token_urlsafe(32)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (id,username,email,password,api_key,role) VALUES (?,?,?,?,?,?)",
            (uid, ADMIN_USER, "admin@veil.local", hpw, akey, "admin")
        )
        conn.commit()
        print(f"[VEIL] Admin API key: {akey}")
    except Exception as e:
        print(f"[VEIL] DB seed note: {e}")
    conn.close()

# ─── HELPERS ───────────────────────────────────────────────────────────────────
def _hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
    return f"{salt}:{h.hex()}"

def _verify_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(h, check.hex())
    except Exception:
        return False

def _make_token(user_id: str, role: str) -> str:
    payload = {
        "sub":  user_id,
        "role": role,
        "iat":  datetime.now(timezone.utc),
        "exp":  datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def _decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def _new_id() -> str:
    return secrets.token_hex(12)

def _client_ip() -> str:
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()

def _validate_url(url: str) -> str | None:
    """Return cleaned URL or None if invalid."""
    url = url.strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,})'
        r'(?::\d+)?(?:/[^\s]*)?$', re.IGNORECASE
    )
    return url if pattern.match(url) else None

# ─── AUTH DECORATORS ────────────────────────────────────────────────────────────
def require_auth(f):
    """JWT or API-key auth. Sets g.user_id and g.role."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        db      = get_db()
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        auth    = request.headers.get("Authorization", "")

        if api_key:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            row = db.execute(
                "SELECT ak.user_id, u.role FROM api_keys ak JOIN users u ON u.id=ak.user_id WHERE ak.key_hash=?",
                (key_hash,)
            ).fetchone()
            if not row:
                return jsonify({"error": "Invalid API key"}), 401
            db.execute("UPDATE api_keys SET last_used=datetime('now') WHERE key_hash=?", (key_hash,))
            db.commit()
            g.user_id = row["user_id"]
            g.role    = row["role"]
            return f(*args, **kwargs)

        if auth.startswith("Bearer "):
            token = auth[7:]
            try:
                payload   = _decode_token(token)
                g.user_id = payload["sub"]
                g.role    = payload.get("role", "user")
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401

        return jsonify({"error": "Authentication required"}), 401
    return wrapper

def optional_auth(f):
    """Like require_auth but doesn't block — sets g.user_id to None if unauthenticated."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        g.user_id = None
        g.role    = "guest"
        db        = get_db()
        api_key   = request.headers.get("X-API-Key") or request.args.get("api_key")
        auth      = request.headers.get("Authorization", "")

        if api_key:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            row = db.execute(
                "SELECT ak.user_id, u.role FROM api_keys ak JOIN users u ON u.id=ak.user_id WHERE ak.key_hash=?",
                (key_hash,)
            ).fetchone()
            if row:
                g.user_id = row["user_id"]
                g.role    = row["role"]
        elif auth.startswith("Bearer "):
            try:
                payload   = _decode_token(auth[7:])
                g.user_id = payload["sub"]
                g.role    = payload.get("role", "user")
            except Exception:
                pass
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if g.role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ─── SECURITY HEADERS ──────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["Referrer-Policy"]        = "no-referrer"
    resp.headers["X-XSS-Protection"]      = "1; mode=block"
    resp.headers["Server"]                 = "VEIL"
    return resp

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "Username must be 3–30 characters"}), 400

    db  = get_db()
    uid = _new_id()
    api = "veil_" + secrets.token_urlsafe(32)
    try:
        db.execute(
            "INSERT INTO users (id,username,email,password,api_key) VALUES (?,?,?,?,?)",
            (uid, username, email or None, _hash_password(password), api)
        )
        # also register the api key in api_keys table
        key_hash = hashlib.sha256(api.encode()).hexdigest()
        db.execute(
            "INSERT INTO api_keys (key_hash,user_id,name) VALUES (?,?,?)",
            (key_hash, uid, "default")
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        if "username" in str(e): return jsonify({"error": "Username taken"}), 409
        if "email"    in str(e): return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": "Registration failed"}), 409

    token = _make_token(uid, "user")
    return jsonify({"token": token, "api_key": api, "user": {"id": uid, "username": username, "role": "user"}}), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("20 per hour")
def login():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    db  = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or not _verify_password(password, row["password"]):
        time.sleep(0.5)   # slow-down brute force
        return jsonify({"error": "Invalid credentials"}), 401

    db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (row["id"],))
    db.commit()
    token = _make_token(row["id"], row["role"])
    return jsonify({
        "token":   token,
        "api_key": row["api_key"],
        "user":    {"id": row["id"], "username": row["username"], "role": row["role"]}
    })


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    db  = get_db()
    row = db.execute("SELECT id,username,email,role,created_at,last_login FROM users WHERE id=?", (g.user_id,)).fetchone()
    if not row: return jsonify({"error": "User not found"}), 404
    return jsonify(dict(row))


@app.route("/api/auth/apikey/rotate", methods=["POST"])
@require_auth
def rotate_api_key():
    db      = get_db()
    old_row = db.execute("SELECT api_key FROM users WHERE id=?", (g.user_id,)).fetchone()
    new_key = "veil_" + secrets.token_urlsafe(32)
    new_hash= hashlib.sha256(new_key.encode()).hexdigest()

    if old_row and old_row["api_key"]:
        old_hash = hashlib.sha256(old_row["api_key"].encode()).hexdigest()
        db.execute("DELETE FROM api_keys WHERE key_hash=?", (old_hash,))

    db.execute("UPDATE users SET api_key=? WHERE id=?", (new_key, g.user_id))
    db.execute("INSERT OR REPLACE INTO api_keys (key_hash,user_id,name) VALUES (?,?,?)",
               (new_hash, g.user_id, "default"))
    db.commit()
    return jsonify({"api_key": new_key})


# ═══════════════════════════════════════════════════════════════════════════════
# AI PROXY
# ═══════════════════════════════════════════════════════════════════════════════

def _call_ai(prompt: str, cfg: dict) -> str:
    url     = cfg.get("url",    AI_URL)
    key     = cfg.get("key",    AI_KEY)
    model   = cfg.get("model",  AI_MODEL)
    fmt     = cfg.get("format", AI_FORMAT)
    maxtok  = int(cfg.get("maxTokens", 1000))
    system  = cfg.get("system", "")

    headers = {"Content-Type": "application/json"}
    if fmt == "anthropic":
        if key: headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
        body = {"model": model, "max_tokens": maxtok, "messages": [{"role": "user", "content": prompt}]}
        if system: body["system"] = system
    else:
        if key: headers["Authorization"] = f"Bearer {key}"
        msgs = []
        if system: msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        body = {"model": model, "max_tokens": maxtok, "messages": msgs}

    r = requests.post(url, headers=headers, json=body, timeout=30)
    r.raise_for_status()
    data = r.json()

    if fmt == "anthropic":
        return "".join(c.get("text", "") for c in data.get("content", []))
    else:
        return "".join(c.get("message", {}).get("content", "") for c in data.get("choices", []))


@app.route("/api/ai/proxy", methods=["POST"])
@optional_auth
@limiter.limit("30 per hour")
def ai_proxy():
    """
    Secure AI proxy — strips API keys from client, uses server-side config.
    Accepts: { prompt, serverCfg (url/model/format only — key is ignored) }
    """
    data   = request.get_json(silent=True) or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt required"}), 400
    if len(prompt) > 8000:
        return jsonify({"error": "Prompt too long"}), 400

    # Client may send url/model/format for custom server, but key ALWAYS comes from server env
    client_cfg = data.get("serverCfg") or {}
    cfg = {
        "url":       client_cfg.get("url")    or AI_URL,
        "model":     client_cfg.get("model")  or AI_MODEL,
        "format":    client_cfg.get("format") or AI_FORMAT,
        "key":       AI_KEY,   # ← always server-side, never client
        "maxTokens": min(int(client_cfg.get("maxTokens") or 1000), 2000),
        "system":    client_cfg.get("system") or ""
    }

    try:
        text = _call_ai(prompt, cfg)
        return jsonify({"text": text})
    except requests.HTTPError as e:
        return jsonify({"error": f"AI server error: {e.response.status_code}"}), 502
    except requests.Timeout:
        return jsonify({"error": "AI server timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# URL SCAN
# ═══════════════════════════════════════════════════════════════════════════════

VEIL_SYSTEM = """You are VEIL, an elite AI trust intelligence system."""

VEIL_PROMPT = """Analyze the following URL for trustworthiness.

URL: {url}

Respond ONLY with a valid JSON object (no markdown, no backticks):
{{
  "trustScore": <integer 0-100>,
  "level": "<Safe|Mostly Safe|Suspicious|Dangerous>",
  "explanation": "<2-3 sentences, calm human empathetic language, specific>",
  "signals": {{
    "domainReputation": <0-100>, "sslSecurity": <0-100>, "contentSafety": <0-100>,
    "scamProbability": <0-100>, "manipulationRisk": <0-100>, "communityTrust": <0-100>
  }},
  "behaviorDNA": {{
    "urgencyPressure": <0-100>, "emotionalManipulation": <0-100>,
    "authorityExploitation": <0-100>, "darkPatternIntensity": <0-100>, "transparencyScore": <0-100>
  }},
  "domain": {{
    "registrar": "<string>", "age": "<string>", "ssl": "<Valid|Invalid|None>",
    "country": "<string>", "ipReputation": "<Clean|Flagged|Unknown>", "lastUpdated": "<string>"
  }},
  "community": {{
    "totalReports": <int>, "scamReports": <int>, "phishingReports": <int>,
    "reputationTrend": "<Improving|Stable|Declining>", "trustVotes": <int>
  }}
}}"""

def _fallback_scan(url: str) -> dict:
    safe_domains    = ["github.com","stripe.com","google.com","anthropic.com","notion.so","microsoft.com","apple.com"]
    danger_patterns = [".tk",".ml","amaz0n","paypal-support","verify.","free-gift","login-secure","account-alert"]
    is_safe    = any(d in url for d in safe_domains)
    is_danger  = any(p in url for p in danger_patterns)
    score = 91 if is_safe else 15 if is_danger else 62
    level = "Safe" if score>80 else "Mostly Safe" if score>60 else "Suspicious" if score>35 else "Dangerous"
    return {
        "trustScore": score, "level": level,
        "explanation": "AI analysis unavailable — local heuristic used. Results may be less accurate.",
        "signals":     {"domainReputation":score,"sslSecurity":score,"contentSafety":score,"scamProbability":100-score,"manipulationRisk":100-score,"communityTrust":score},
        "behaviorDNA": {"urgencyPressure":100-score,"emotionalManipulation":100-score,"authorityExploitation":100-score,"darkPatternIntensity":100-score,"transparencyScore":score},
        "domain":      {"registrar":"Unknown","age":"Unknown","ssl":"Unknown","country":"Unknown","ipReputation":"Unknown","lastUpdated":"Unknown"},
        "community":   {"totalReports":0,"scamReports":0,"phishingReports":0,"reputationTrend":"Stable","trustVotes":0}
    }


@app.route("/api/scan", methods=["POST"])
@optional_auth
@limiter.limit("60 per hour; 10 per minute")
def scan():
    data  = request.get_json(silent=True) or {}
    url   = _validate_url(data.get("url") or "")
    if not url:
        return jsonify({"error": "Valid URL required"}), 400

    db    = get_db()
    ip    = _client_ip()

    # ── Check cache (last 1 h same URL) ─────────────────────────────────────
    cached = db.execute(
        """SELECT result FROM scan_history
           WHERE url=? AND datetime(created_at) > datetime('now','-1 hour')
           ORDER BY created_at DESC LIMIT 1""",
        (url,)
    ).fetchone()

    if cached:
        result = json.loads(cached["result"])
        result["cached"] = True
        return jsonify(result)

    # ── AI analysis ──────────────────────────────────────────────────────────
    client_cfg = data.get("serverCfg") or {}
    cfg = {
        "url":       client_cfg.get("url")    or AI_URL,
        "model":     client_cfg.get("model")  or AI_MODEL,
        "format":    client_cfg.get("format") or AI_FORMAT,
        "key":       AI_KEY,
        "maxTokens": 1200,
        "system":    VEIL_SYSTEM
    }

    try:
        raw     = _call_ai(VEIL_PROMPT.format(url=url), cfg)
        cleaned = raw.replace("```json","").replace("```","").strip()
        result  = json.loads(cleaned)
    except Exception as e:
        print(f"[VEIL] AI error: {e}")
        result  = _fallback_scan(url)

    result["cached"] = False
    result["url"]    = url

    # Merge community data from DB reports
    rep_row = db.execute(
        "SELECT COUNT(*) total, SUM(type='scam') scam, SUM(type='phishing') phish FROM reports WHERE url=?",
        (url,)
    ).fetchone()
    if rep_row and rep_row["total"]:
        result["community"]["totalReports"]    = int(rep_row["total"])
        result["community"]["scamReports"]     = int(rep_row["scam"] or 0)
        result["community"]["phishingReports"] = int(rep_row["phish"] or 0)

    # ── Save to history ──────────────────────────────────────────────────────
    scan_id = _new_id()
    db.execute(
        "INSERT INTO scan_history (id,user_id,url,trust_score,level,result,ip) VALUES (?,?,?,?,?,?,?)",
        (scan_id, g.user_id, url, result.get("trustScore"), result.get("level"), json.dumps(result), ip)
    )
    db.commit()

    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/history", methods=["GET"])
@require_auth
def history():
    db    = get_db()
    limit = min(int(request.args.get("limit", 20)), 100)
    rows  = db.execute(
        """SELECT id,url,trust_score,level,created_at
           FROM scan_history WHERE user_id=?
           ORDER BY created_at DESC LIMIT ?""",
        (g.user_id, limit)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/history/<scan_id>", methods=["GET"])
@require_auth
def history_detail(scan_id):
    db  = get_db()
    row = db.execute(
        "SELECT * FROM scan_history WHERE id=? AND user_id=?",
        (scan_id, g.user_id)
    ).fetchone()
    if not row: return jsonify({"error": "Not found"}), 404
    data = dict(row)
    data["result"] = json.loads(data["result"] or "{}")
    return jsonify(data)


@app.route("/api/history/<scan_id>", methods=["DELETE"])
@require_auth
def delete_history(scan_id):
    db = get_db()
    db.execute("DELETE FROM scan_history WHERE id=? AND user_id=?", (scan_id, g.user_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/history", methods=["DELETE"])
@require_auth
def clear_history():
    db = get_db()
    db.execute("DELETE FROM scan_history WHERE user_id=?", (g.user_id,))
    db.commit()
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

VALID_TYPES = {"scam","phishing","fake","manipulation","malware","other"}

@app.route("/api/reports", methods=["POST"])
@optional_auth
@limiter.limit("20 per hour")
def submit_report():
    data    = request.get_json(silent=True) or {}
    url     = _validate_url(data.get("url") or "")
    rtype   = (data.get("type") or "").strip().lower()
    details = (data.get("details") or "")[:1000]

    if not url:
        return jsonify({"error": "Valid URL required"}), 400
    if rtype not in VALID_TYPES:
        return jsonify({"error": f"type must be one of: {', '.join(sorted(VALID_TYPES))}"}), 400

    db  = get_db()
    ip  = _client_ip()

    # Prevent spam: same IP + URL + type within 24h
    dup = db.execute(
        "SELECT id FROM reports WHERE ip=? AND url=? AND type=? AND datetime(created_at)>datetime('now','-1 day')",
        (ip, url, rtype)
    ).fetchone()
    if dup:
        return jsonify({"error": "Duplicate report — already submitted recently"}), 429

    rid = _new_id()
    db.execute(
        "INSERT INTO reports (id,user_id,url,type,details,ip) VALUES (?,?,?,?,?,?)",
        (rid, g.user_id, url, rtype, details, ip)
    )
    db.commit()
    return jsonify({"ok": True, "report_id": rid}), 201


@app.route("/api/reports", methods=["GET"])
@require_auth
def list_reports():
    db    = get_db()
    url   = request.args.get("url")
    limit = min(int(request.args.get("limit", 50)), 200)

    if url:
        rows = db.execute(
            "SELECT id,url,type,status,created_at FROM reports WHERE url=? ORDER BY created_at DESC LIMIT ?",
            (url, limit)
        ).fetchall()
    elif g.role == "admin":
        rows = db.execute(
            "SELECT id,url,type,status,created_at,ip FROM reports ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id,url,type,status,created_at FROM reports WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (g.user_id, limit)
        ).fetchall()

    return jsonify([dict(r) for r in rows])


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    db = get_db()
    stats = {
        "users":   db.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
        "scans":   db.execute("SELECT COUNT(*) n FROM scan_history").fetchone()["n"],
        "reports": db.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"],
        "scans_today": db.execute(
            "SELECT COUNT(*) n FROM scan_history WHERE date(created_at)=date('now')"
        ).fetchone()["n"],
        "top_scanned": [dict(r) for r in db.execute(
            "SELECT url, COUNT(*) cnt FROM scan_history GROUP BY url ORDER BY cnt DESC LIMIT 10"
        ).fetchall()],
        "recent_reports": [dict(r) for r in db.execute(
            "SELECT url,type,status,created_at FROM reports ORDER BY created_at DESC LIMIT 20"
        ).fetchall()]
    }
    return jsonify(stats)


@app.route("/api/admin/reports/<report_id>", methods=["PATCH"])
@require_admin
def update_report(report_id):
    data   = request.get_json(silent=True) or {}
    status = data.get("status","").strip()
    if status not in {"pending","reviewed","actioned","dismissed"}:
        return jsonify({"error": "Invalid status"}), 400
    db = get_db()
    db.execute("UPDATE reports SET status=? WHERE id=?", (status, report_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def admin_users():
    db   = get_db()
    rows = db.execute(
        "SELECT id,username,email,role,created_at,last_login FROM users ORDER BY created_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH & INFO
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health():
    try:
        db = get_db()
        db.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({
        "status":    "ok" if db_ok else "degraded",
        "db":        "connected" if db_ok else "error",
        "ai_url":    AI_URL,
        "ai_model":  AI_MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/config/server", methods=["GET"])
def server_config_info():
    """Returns public server config (no secrets) so the frontend can auto-detect."""
    return jsonify({
        "ai_url":    AI_URL,
        "ai_model":  AI_MODEL,
        "ai_format": AI_FORMAT,
        "version":   "1.0.0"
    })


# ─── ERROR HANDLERS ────────────────────────────────────────────────────────────
@app.errorhandler(429)
def too_many(e):
    return jsonify({"error": "Rate limit exceeded. Slow down."}), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print(f"""
╔══════════════════════════════════════════╗
║       VEIL Backend  —  v1.0.0            ║
╠══════════════════════════════════════════╣
║  http://localhost:{PORT:<5}                  ║
║  AI  : {AI_MODEL[:32]:<32} ║
║  DB  : {str(DB_PATH)[:32]:<32} ║
╚══════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=PORT, debug=False)
