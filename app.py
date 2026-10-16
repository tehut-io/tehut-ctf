#!/usr/bin/env python3
"""Tehut Security CTF (https://tehut.io): the Pixel Palace Arcade engagement.

A deliberately vulnerable OWASP Top 10 playground.

    !!!  THIS APPLICATION IS INTENTIONALLY INSECURE (it includes real RCE).  !!!
    !!!  Run it only on your own machine or in Docker. Never expose it.      !!!

Run:   python3 app.py          -> http://127.0.0.1:5000
       docker compose up       -> http://127.0.0.1:5000

Lines marked "# VULN:" are the intentional bugs. Try playing black-box first!
"""

import base64
import hashlib
import hmac
import json
import math
import os
import pickle
import re
import secrets
import sqlite3
import subprocess
import threading
import traceback
import urllib.parse
import urllib.request
from datetime import datetime

from flask import (Flask, abort, jsonify, make_response, redirect, render_template,
                   render_template_string, request)
from werkzeug.exceptions import HTTPException

from challenges import BY_KEY, CATEGORIES, CHALLENGES, HINT_COST, rank_for

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LAB_DATA_DIR", os.path.join(BASE, "data"))
DB_PATH = os.path.join(DATA_DIR, "lab.db")
LOG_PATH = os.path.join(DATA_DIR, "access.log")
SECRETS_DIR = os.path.join(BASE, "data", "secrets")  # challenge text says data/secrets/
STATE_PATH = os.path.join(DATA_DIR, "progress.json")

HOST = os.environ.get("LAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("LAB_PORT", "5000"))
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]"} | {
    h.strip() for h in os.environ.get("LAB_ALLOWED_HOSTS", "").split(",") if h.strip()}

PLAYER = "intern"
PLAYER_PASSWORD = "intern"
MILLION = 1_000_000

app = Flask(__name__)
app.config["SECRET_KEY"] = "pixel-palace-1986"  # VULN-ish: hardcoded, but nothing here uses it ;)

# ====================================================================== CTF state
# Progress lives in data/progress.json so it survives restarts. The random
# "secret" makes every install's flags unique.
_state_lock = threading.Lock()


def _load_state():
    try:
        with open(STATE_PATH) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    st.setdefault("secret", secrets.token_hex(16))
    st.setdefault("solved", {})
    st.setdefault("hints", {})
    return st


def save_state():
    with _state_lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(STATE, f, indent=2)
        os.replace(tmp, STATE_PATH)


os.chdir(BASE)  # so relative paths like data/secrets/... work for RCE payloads
os.makedirs(DATA_DIR, exist_ok=True)
STATE = _load_state()


def _hmac(label):
    return hmac.new(STATE["secret"].encode(), label.encode(), hashlib.sha256).hexdigest()


def flag(key):
    return "FLAG{%s_%s}" % (BY_KEY[key]["slug"], _hmac("flag:" + key)[:6])


def hint_penalty(key, used):
    pts = BY_KEY[key]["points"]
    return sum(round(pts * HINT_COST[i]) for i in range(used))


def progress():
    solved = {k: v for k, v in STATE["solved"].items() if k in BY_KEY}
    score = sum(v["points"] for v in solved.values())
    max_score = sum(c["points"] for c in CHALLENGES)
    pct = score / max_score if max_score else 0
    return {"score": score, "max_score": max_score, "solved": len(solved),
            "total": len(CHALLENGES), "pct": round(pct * 100), "rank": rank_for(pct)}


# ====================================================================== lab state
# Runtime-only state; wiped by init_db() ("Reset lab" in HQ, or a restart).
SESSIONS = {}          # sessid -> username
INBOX = {}             # username -> [mail]
XSS_TOKENS = {}        # token -> challenge key
RUNTIME = {}           # misc counters


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def locker_pin():
    return "%04d" % (int(_hmac("locker-pin")[:8], 16) % 10000)


INTERNAL_KEY = secrets.token_hex(16)  # header the link-preview fetcher sends


def db(readonly=False):
    if readonly:
        conn = sqlite3.connect("file:%s?mode=ro" % DB_PATH, uri=True)
    else:
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    os.makedirs(SECRETS_DIR, exist_ok=True)
    for name, key in (("ping_flag.txt", "a03_cmd"), ("pickle_flag.txt", "a08_pickle")):
        with open(os.path.join(SECRETS_DIR, name), "w") as f:
            f.write(flag(key) + "\n")

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = db()
    c = conn.cursor()
    c.execute("""CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                 password_hash TEXT, role TEXT, email TEXT, balance REAL, notes TEXT)""")
    c.execute("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    c.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, content TEXT, ts TEXT)")
    c.execute("CREATE TABLE cheat_codes (id INTEGER PRIMARY KEY, label TEXT, secret TEXT)")

    users = [
        (1, "admin", md5(secrets.token_hex(12)), "admin", "admin@pixelpalace.local", 5_000_000,
         "Floor manager. Always on shift. Reads every help desk message personally."),
        (2, "alice", md5(secrets.token_hex(12)), "staff", "alice@pixelpalace.local", 12_500,
         "PRIZE COUNTER - PRIVATE - who really won the giant panda plush | " + flag("a01_idor")),
        (3, "bob", md5(secrets.token_hex(12)), "technician", "bob@pixelpalace.local", 3_200,
         "My prize locker PIN is 4 digits. Nobody will ever guess it!"),
        (4, "owner", md5("sunshine"), "owner", "owner@pixelpalace.local", 2_000_000,
         "Secret memo is on my account page. Password is my favourite weather."),
        (5, PLAYER, md5(PLAYER_PASSWORD), "staff", "intern@pixelpalace.local", 100,
         "Hi! I'm the new intern. I'm mostly here for the free plays :)"),
    ]
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?)", users)
    c.executemany("INSERT INTO posts (title, body) VALUES (?,?)", [
        ("New cabinet: Street Brawler II Turbo", "Arrives Friday. Staff may NOT hog it during opening hours."),
        ("Claw machine #3 out of order", "Again. Please stop trying to win the panda with a broom."),
        ("Password rotation notice", "Rotate your password every 90 days. 'Pacman1' -> 'Pacman2' is fine."),
        ("New: Pixel Postcards", "Send greeting cards to the crew with our templating engine!"),
        ("Retro night is back", "Neon, synths and leg warmers. Every Friday. Tokens half price."),
    ])
    c.executemany("INSERT INTO comments (author, content, ts) VALUES (?,?,?)", [
        ("alice", "AAA was here. 999,999 on Galaxy Raiders. Beat that.", now()),
        ("bob", "Whoever left gum in the pinball machine: I will find you.", now()),
    ])
    c.executemany("INSERT INTO cheat_codes (label, secret) VALUES (?,?)", [
        ("prize-shop-api-key", "sk_live_EXAMPLE_not_real"),
        ("ctf-flag", flag("a03_sqli")),
    ])
    conn.commit()
    conn.close()

    SESSIONS.clear()
    SESSIONS[md5("admin")] = "admin"   # the manager is logged in somewhere...
    XSS_TOKENS.clear()
    RUNTIME.clear()
    RUNTIME.update(locker_attempts=0, log_forged=False)
    INBOX.clear()
    INBOX[PLAYER] = [{
        "from": "operations@tehut.io", "ts": now(),
        "subject": "[Tehut Security] Your engagement brief ;)",
        "body": "Hi operator,\n\nOfficially you're Pixel Palace Arcade's new intern. Unofficially, the "
                "arcade hired Tehut Security to find out how broken this place is before real attackers "
                "do, and you're our player on the inside.\n\n"
                "Your account: intern / intern\n\nYour mission briefing and scoreboard are in "
                "Tehut HQ (/hq). Every flag you capture goes there.\n\nPlayer 1, ready? Don't get caught.\n"
                "- Tehut Security Operations | https://tehut.io",
    }]
    with open(LOG_PATH, "w") as f:
        f.write("%s SYSTEM cabinets powered on\n%s LOGIN SUCCESS user=bob ip=10.0.0.23\n"
                "%s LOGIN FAILED user=alice ip=10.0.0.17\n" % (now(), now(), now()))


# ====================================================================== helpers
def current_user():
    uname = SESSIONS.get(request.cookies.get("sessid", ""))
    if not uname:
        return None
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (uname,)).fetchone()
    conn.close()
    return row


def render(title, body, **ctx):
    """Render an arcade page. `body` is a constant Jinja snippet (never user input)."""
    tpl = "{% extends 'base.html' %}{% block content %}" + body + "{% endblock %}"
    return render_template_string(tpl, title=title, **ctx)


def need_login(what="do that"):
    return render("Login required", """
      <div class="card narrow"><h1>🔒 Login required</h1>
      <p>You need to be logged in to {{ what }}.</p>
      <a class="btn" href="/login">Log in</a></div>""", what=what), 401


def xss_token(key):
    tok = secrets.token_hex(8)
    if len(XSS_TOKENS) > 500:
        XSS_TOKENS.clear()
    XSS_TOKENS[tok] = key
    return tok


def log_event(kind, username):
    line = "%s %s user=%s ip=%s" % (now(), kind, username, request.remote_addr)
    parts = re.split(r"\r\n|\r|\n", line)
    # VULN: the username is written verbatim; CR/LF lets you inject whole log lines.
    if any("LOGIN SUCCESS" in p and "user=admin" in p for p in parts[1:]):
        RUNTIME["log_forged"] = True
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")


def do_gift(sender, to, raw_amount):
    """Move tokens between users. Returns (ok, message, amount)."""
    try:
        amount = float(raw_amount)
    except (TypeError, ValueError):
        return False, "Amount must be a number.", 0
    if not math.isfinite(amount):
        return False, "Nice try. Amount must be finite.", 0
    # VULN: no server-side check that amount > 0 (the form has min="1"...)
    conn = db()
    src = conn.execute("SELECT * FROM users WHERE username = ?", (sender,)).fetchone()
    dst = conn.execute("SELECT * FROM users WHERE username = ?", (to,)).fetchone()
    if not dst:
        conn.close()
        return False, "Unknown recipient '%s'." % to, amount
    if dst["username"] == src["username"]:
        conn.close()
        return False, "You can't gift tokens to yourself.", amount
    if src["balance"] < amount:
        conn.close()
        return False, "Not enough tokens. Insert more coins!", amount
    conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, src["id"]))
    conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, dst["id"]))
    conn.commit()
    conn.close()
    return True, "Gifted %s tokens from %s to %s." % ("{:,.0f}".format(amount), sender, to), amount


def membership_cookie(username, tier="basic"):
    return base64.b64encode(json.dumps({"user": username, "tier": tier}).encode()).decode()


@app.context_processor
def inject_globals():
    return {"me": current_user(), "progress": progress(), "xss": None}


# ====================================================================== safety rails
# These protect *your* machine while the lab runs: other websites can't drive
# the RCE endpoints from your browser (cross-site requests / DNS rebinding).
@app.before_request
def guard():
    if request.headers.get("X-Palace-Fetcher") == INTERNAL_KEY:
        return None  # the lab's own link-preview fetcher (SSRF challenge)
    host = request.host
    host = host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
    if host not in ALLOWED_HOSTS:
        return ("Host '%s' not allowed (DNS-rebinding protection). "
                "Set LAB_ALLOWED_HOSTS=%s to allow it.\n" % (host, host)), 403
    if request.headers.get("Sec-Fetch-Site") in ("cross-site", "same-site"):
        return "Cross-site request blocked: this lab only accepts requests from itself.\n", 403
    return None


# ====================================================================== errors (A05)
@app.errorhandler(Exception)
def on_error(e):
    if isinstance(e, HTTPException):
        if e.code == 404:
            return render("Not found", """
              <div class="card narrow center"><p class="eyebrow">404</p><h1 class="blink-slow">GAME OVER</h1>
              <p>This page doesn't exist. Continue?</p>
              <a class="btn" href="/">Insert coin ▶</a></div>"""), 404
        return e
    # VULN: debug mode in production, so full traceback and config go to the client.
    tb = "".join(traceback.format_exception(e))
    env = {
        "FLASK_ENV": "production",
        "DEBUG": "True   # TODO(ops): disable before go-live!!",
        "SECRET_KEY": app.config["SECRET_KEY"],
        "DATABASE_URL": "sqlite:///data/lab.db",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "INTERNAL_DEBUG_FLAG": flag("a05_debug"),
    }
    return render_template("debug.html", tb=tb, err=repr(e), env=env, path=request.full_path), 500


# ====================================================================== public pages
@app.route("/")
def index():
    posts = db().execute("SELECT title, body FROM posts LIMIT 3").fetchall()
    return render("Pixel Palace Arcade", """
      <section class="hero">
        <div>
          <p class="eyebrow">Pixel Palace Arcade · staff portal · est. 1986</p>
          <h1>High scores.<br><span class="neon-pink">Low security.</span></h1>
          <p class="lead">Welcome to the staff portal. Our security is <i>totally radical</i>,
             says our 1994 audit.</p>
          {% if not me %}<a class="btn" href="/login">▶ Staff login</a>{% else %}
          <a class="btn" href="/account">▶ My account</a>{% endif %}
          <a class="btn ghost" href="/hq">🏴 Open Tehut HQ</a>
        </div>
        <div class="hero-card">
          <p class="insert-coin">INSERT COIN</p>
          <p class="eyebrow">Player 1, new here?</p>
          <p>You're the <b>intern</b>. Your login is <code>intern</code> / <code>intern</code>.</p>
          <p>Your real job, courtesy of <a href="https://tehut.io" target="_blank" rel="noopener">Tehut
             Security</a>: break this arcade. Mission briefing and scoreboard live in
             <a href="/hq">Tehut HQ</a>. Look for 🚩 flags, then click one to submit it.</p>
        </div>
      </section>
      <div class="grid two">
        <section class="card hiscores">
          <h2>🏆 Hall of fame</h2>
          <ol>
            <li><span>AAA</span><span>999,999</span></li>
            <li><span>BOB</span><span>874,300</span></li>
            <li><span>JOY</span><span>650,050</span></li>
            <li><span>ZAP</span><span>420,690</span></li>
            <li><span>INT</span><span class="muted">000,100</span></li>
          </ol>
        </section>
        <section>
          <h2>📰 Arcade news</h2>
          {% for p in posts %}<article class="card news"><h3>{{ p.title }}</h3><p>{{ p.body }}</p></article>{% endfor %}
          <p class="muted"><a href="/search">Search all news →</a></p>
        </section>
      </div>""", posts=posts)


@app.route("/robots.txt")
def robots():
    txt = ("User-agent: *\n"
           "Disallow: /admin\n"
           "Disallow: /api/v1/admin/\n"
           "Disallow: /backup/\n"
           "Disallow: /internal/\n")
    return app.response_class(txt, mimetype="text/plain")


@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    tok = xss_token("a03_xss_reflected") if "<" in name else None
    # VULN: reflected XSS. |safe disables Jinja's auto-escaping.
    return render("High score", """
      <div class="card narrow center hiscreen">
        <p class="eyebrow">Galaxy Raiders · game over</p>
        <p class="insert-coin">NEW HIGH SCORE!</p>
        <h1>Well played, {{ name|safe }}! 🏆</h1>
        <form><label>Enter your name for the leaderboard
          <input name="name" placeholder="AAA" value="{{ name }}"></label>
        <button class="btn">Save score</button></form>
      </div>""", name=name, xss=tok)


# ====================================================================== auth
LOGIN_FORM = """
  <div class="card narrow">
    <h1>Staff login</h1>
    {% if error %}<div class="alert bad">{{ error }}</div>{% endif %}
    <form method="post">
      <label>Username <input name="username" value="{{ username }}" autofocus></label>
      <label>Password <input name="password" type="password"></label>
      <button class="btn">Log in</button>
    </form>
    <p class="muted">Intern? Use <code>intern</code> / <code>intern</code>.
       Forgot your password? <a href="/reset">Reset it</a>.</p>
  </div>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render("Login", LOGIN_FORM, error=None, username="")
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?",
                       (u, md5(p))).fetchone()
    conn.close()
    if not row:
        log_event("LOGIN FAILED", u)
        return render("Login", LOGIN_FORM, error="Invalid credentials. (This attempt was logged.)",
                      username=u), 401
    sid = md5(row["username"])  # VULN: predictable session id
    SESSIONS[sid] = row["username"]
    log_event("LOGIN SUCCESS", row["username"])
    resp = make_response(redirect("/account"))
    resp.set_cookie("sessid", sid)
    # VULN: authorization data in an unsigned client-side cookie
    resp.set_cookie("membership", membership_cookie(row["username"]))
    return resp


@app.route("/logout")
def logout():
    SESSIONS.pop(request.cookies.get("sessid", ""), None)
    resp = make_response(redirect("/"))
    resp.delete_cookie("sessid")
    resp.delete_cookie("membership")
    return resp


@app.route("/account")
def account():
    me = current_user()
    if not me:
        return need_login("see your account")
    return render("My account", """
      <h1>Hi, {{ me.username }} 👋</h1>
      <div class="grid">
        <div class="card stat"><p class="eyebrow">Token balance</p>
          <p class="big">🪙 {{ "{:,.0f}".format(me.balance) }} <small>tokens</small></p>
          <a href="/gift">Gift tokens →</a></div>
        <div class="card stat"><p class="eyebrow">Role</p><p class="big">{{ me.role }}</p>
          <a href="/profile?id={{ me.id }}">View profile →</a></div>
        <div class="card stat"><p class="eyebrow">Membership</p><p class="big">⭐</p>
          <a href="/vip">VIP Gold Club →</a></div>
      </div>
      {% if me.username == 'admin' %}
        <div class="card loud"><h2>🛡️ Floor manager dashboard</h2>
        <p>Welcome back, boss. All cabinets online. Definitely nobody forged this session.</p>
        <p><code>{{ f_session }}</code></p></div>
      {% elif me.username == 'owner' %}
        <div class="card loud"><h2>🤫 Owner's secret memo</h2>
        <p>Plan for Q3: quietly set every claw machine to "never win". Funded by cancelling the intern's pizza budget.</p>
        <p><code>{{ f_owner }}</code></p></div>
      {% endif %}
      <div class="grid">
        <a class="card link" href="/inbox"><h3>📬 Inbox</h3><p>Messages for you.</p></a>
        <a class="card link" href="/settings"><h3>💾 Save file</h3><p>Export / import your game settings.</p></a>
        <a class="card link" href="/session"><h3>🍪 Session</h3><p>Your session details.</p></a>
      </div>""", f_session=flag("a07_session"), f_owner=flag("a02_crack"))


@app.route("/session")
def session_info():
    me = current_user()
    return render("Session", """
      <div class="card narrow"><h1>🍪 Session details</h1>
      <table class="kv">
        <tr><th>Cookie <code>sessid</code></th><td><code>{{ sid or '(none)' }}</code></td></tr>
        <tr><th>Resolves to</th><td>{{ me.username if me else 'nobody (not logged in)' }}</td></tr>
        <tr><th>Algorithm</th><td>Proprietary PalaceSecure™ ID generator v1</td></tr>
        <tr><th>Active sessions</th><td>{{ n }}</td></tr>
      </table></div>""", sid=request.cookies.get("sessid", ""), n=len(SESSIONS))


@app.route("/inbox")
def inbox():
    me = current_user()
    if not me:
        return need_login("read your mail")
    mails = list(reversed(INBOX.get(me["username"], [])))
    return render("Inbox", """
      <h1>📬 Inbox</h1>
      {% for m in mails %}
        <details class="card mail" {% if loop.first %}open{% endif %}>
          <summary><b>{{ m.subject }}</b> <span class="muted">· {{ m['from'] }} · {{ m.ts }}</span></summary>
          <pre class="mailbody">{{ m.body }}</pre></details>
      {% else %}<p class="muted">No mail. Lonely.</p>{% endfor %}""", mails=mails)


# ====================================================================== A01
@app.route("/profile")
def profile():
    me = current_user()
    if not me:
        return need_login("view profiles")
    uid = int(request.args.get("id", me["id"]))  # VULN (A05): crashes on non-numbers, debug page
    conn = db()
    # VULN (A01): no check that the profile belongs to the logged-in user
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not row:
        return render("Profile", "<div class='card narrow'><h1>No such user</h1></div>"), 404
    return render("Profile", """
      <div class="card narrow">
        <p class="eyebrow">Staff profile #{{ row.id }}</p>
        <h1>{{ row.username }}</h1>
        <table class="kv"><tr><th>Email</th><td>{{ row.email }}</td></tr>
        <tr><th>Role</th><td>{{ row.role }}</td></tr></table>
        <h3>🔒 Private notes</h3><pre>{{ row.notes }}</pre>
      </div>""", row=row)


@app.route("/admin")
def admin():
    me = current_user()
    if not me or me["role"] != "admin":
        return render("Access denied", """
          <div class="card narrow center"><h1>⛔ Staff only</h1>
          <p>The admin console is for the floor manager only.<br>This incident has been
          logged<sup>*</sup>.</p><p class="muted"><small>* it hasn't</small></p></div>"""), 403
    users = db().execute("SELECT id, username, role, email, balance FROM users").fetchall()
    return render("Admin console", """
      <h1>🛡️ Admin console</h1><table class="table"><tr><th>#</th><th>User</th><th>Role</th>
      <th>Email</th><th>Tokens</th></tr>{% for u in users %}<tr><td>{{ u.id }}</td>
      <td>{{ u.username }}</td><td>{{ u.role }}</td><td>{{ u.email }}</td>
      <td>{{ "{:,.0f}".format(u.balance) }}</td></tr>{% endfor %}</table>""", users=users)


@app.route("/api/v1/admin/users")
def api_admin_users():
    # VULN: the API behind the admin console forgot its authorization check
    rows = db().execute("SELECT id, username, role, email FROM users").fetchall()
    return jsonify({"users": [dict(r) for r in rows],
                    "_debug": {"note": "TODO add auth before launch", "flag": flag("a01_api")}})


GIFT_FORM = """
  <div class="card narrow">
    <h1>🪙 Gift tokens</h1>
    <p>Your balance: <b>{{ "{:,.0f}".format(me.balance) }}</b> tokens</p>
    {% if msg %}<div class="alert {{ 'good' if ok else 'bad' }}">{{ msg }}</div>{% endif %}
    {% if tycoon %}<div class="alert good">🤑 TOKEN TYCOON! A million tokens and counting. <code>{{ f_logic }}</code></div>{% endif %}
    <form method="get">
      <label>Gift to <input name="to" placeholder="alice" required></label>
      <label>Tokens <input name="amount" type="number" min="1" step="1" placeholder="10" required></label>
      <button class="btn">Send tokens</button>
    </form>
    <p class="muted">The crew: alice, bob, owner, admin.</p>
  </div>"""


@app.route("/gift")
def gift():
    me = current_user()
    if not me:
        return need_login("gift tokens")
    ok, msg, tycoon = None, None, False
    if "to" in request.args or "amount" in request.args:
        # VULN (A01): state change on GET, no CSRF token
        ok, msg, amount = do_gift(me["username"], request.args.get("to", ""),
                                  request.args.get("amount", ""))
        me = current_user()
        tycoon = ok and amount < 0 and me["balance"] >= MILLION
    return render("Gift tokens", GIFT_FORM, me=me, ok=ok, msg=msg,
                  tycoon=tycoon, f_logic=flag("a04_logic"))


@app.route("/support", methods=["GET", "POST"])
def support():
    me = current_user()
    if not me:
        return need_login("use the help desk")
    visits, got_paid = [], False
    message = request.form.get("message", "")
    if request.method == "POST":
        # The "manager bot": loads every src=/href= and bare URL in the message
        # *with the admin's session*, like a real browser would.
        urls = re.findall(r"""(?:src|href)\s*=\s*["']?([^"'\s>]+)""", message, re.I)
        urls += re.findall(r"""https?://[^\s"'<>]+""", message)
        seen = []
        for u in urls:
            u = u.replace("&amp;", "&")
            if u not in seen:
                seen.append(u)
        for u in seen[:10]:
            p = urllib.parse.urlparse(u)
            if p.path.rstrip("/") == "/gift":
                q = urllib.parse.parse_qs(p.query)
                to, amt = q.get("to", [""])[0], q.get("amount", [""])[0]
                ok, msg, amount = do_gift("admin", to, amt)
                visits.append((u, msg))
                if ok and to == me["username"] and amount > 0:
                    got_paid = True
            else:
                visits.append((u, "Page loaded. Nothing interesting happened."))
    return render("Help desk", """
      <div class="card narrow">
        <h1>🎧 Help desk</h1>
        <p>Messages go straight to the floor manager, <b>admin</b>, who is always logged in and
           opens <i>every</i> link and image. Very diligent. Very trusting.</p>
        <form method="post">
          <label>Message (HTML allowed for rich formatting!)
          <textarea name="message" rows="5" placeholder="Hi boss, check out my high score screenshot...">{{ message }}</textarea></label>
          <button class="btn">Send to manager</button>
        </form>
        {% if request.method == 'POST' %}
          <h3>👔 The floor manager read your message</h3>
          {% if visits %}<ul class="log">{% for u, r in visits %}
            <li><code>GET {{ u }}</code><br><span class="muted">→ {{ r }}</span></li>{% endfor %}</ul>
          {% else %}<p class="muted">No links or images. The manager replied "ok 👍".</p>{% endif %}
          {% if got_paid %}<div class="alert good">🪙 The manager just gifted you tokens. Oops!
            <code>{{ f_csrf }}</code></div>{% endif %}
        {% endif %}
      </div>""", message=message, visits=visits, got_paid=got_paid, f_csrf=flag("a01_csrf"))


# ====================================================================== A02
BACKUP_README = "Nightly staff table backups.\nTODO: move these OFF the web server!!! - Bob (tech)\n"


@app.route("/backup/")
def backup_list():
    files = ["README.txt", "pixelpalace_staff_2026-03.sql.bak"]
    return render("Index of /backup/", """
      <div class="card narrow"><h1>Index of /backup/</h1><ul class="files">
      {% for f in files %}<li>📄 <a href="/backup/{{ f }}">{{ f }}</a></li>{% endfor %}
      </ul><p class="muted"><small>Apache/2.2.3 Server at staff.pixelpalace.local</small></p></div>""",
                  files=files)


@app.route("/backup/<name>")
def backup_file(name):
    if name == "README.txt":
        return app.response_class(BACKUP_README, mimetype="text/plain")
    if name != "pixelpalace_staff_2026-03.sql.bak":
        abort(404)
    rows = db().execute("SELECT id, username, password_hash, role, email FROM users").fetchall()
    out = ["-- Pixel Palace staff dump", "-- passwords are encrypted with MD5 (very secure)", ""]
    for r in rows:
        out.append("INSERT INTO users VALUES (%d, '%s', '%s', '%s', '%s');" % tuple(r))
    return app.response_class("\n".join(out) + "\n", mimetype="text/plain")


# ====================================================================== A03
@app.route("/search")
def search():
    q = request.args.get("q", "")
    error, rows = None, []
    # VULN: SQL built with string concatenation
    sql = "SELECT id, title, body FROM posts WHERE title LIKE '%" + q + "%' OR body LIKE '%" + q + "%'"
    try:
        conn = db(readonly=True)
        rows = conn.execute(sql).fetchall()
        conn.close()
    except sqlite3.Error as e:
        error = str(e)
    return render("News search", """
      <h1>🔎 Arcade news search</h1>
      <form class="inline"><input name="q" value="{{ q }}" placeholder="claw, cabinet, retro...">
      <button class="btn">Search</button></form>
      {% if error %}<div class="alert bad"><b>Database error:</b> {{ error }}
        <pre>{{ sql }}</pre></div>{% endif %}
      <p class="muted">{{ rows|length }} result(s)</p>
      <div class="grid">{% for r in rows %}
        <article class="card"><h3>{{ r[1] }}</h3><p>{{ r[2] }}</p></article>{% endfor %}</div>""",
                  q=q, error=error, rows=rows, sql=sql)


def script_filter(s):
    # VULN: blocklist that only knows about <script> tags
    return re.sub(r"(?i)<\s*/?\s*script[^>]*>", "", s)


@app.route("/comments", methods=["GET", "POST"])
def comments():
    me = current_user()
    if request.method == "POST":
        content = script_filter(request.form.get("content", ""))[:2000]
        if content.strip():
            conn = db()
            conn.execute("INSERT INTO comments (author, content, ts) VALUES (?,?,?)",
                         (me["username"] if me else "anonymous", content, now()))
            conn.commit()
            conn.close()
        return redirect("/comments")
    rows = db().execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    tok = xss_token("a03_xss_stored") if any("<" in r["content"] for r in rows) else None
    return render("Graffiti wall", """
      <h1>🎨 Graffiti wall</h1>
      <div class="card"><form method="post">
        <label>Leave your mark <input name="content" placeholder="GG, everyone! 🕹️" maxlength="2000"></label>
        <button class="btn">Tag it</button>
        <span class="muted"><small>🛡️ Protected by ScriptStrip™: &lt;script&gt; tags are removed.</small></span>
      </form></div>
      {% for c in rows %}
        <div class="comment"><b>{{ c.author }}</b> <span class="muted">{{ c.ts }}</span>
        <div>{{ c.content|safe }}</div></div>
      {% endfor %}
      <form method="post" action="/comments/clear"><button class="btn ghost small">🧽 Clean the wall</button></form>
      """, rows=rows, xss=tok)


@app.route("/comments/clear", methods=["POST"])
def comments_clear():
    conn = db()
    conn.execute("DELETE FROM comments WHERE id > 2")
    conn.commit()
    conn.close()
    return redirect("/comments")


@app.route("/tools")
def tools():
    return render("Tools", """
      <h1>🧰 Staff tools</h1>
      <div class="grid">
        <a class="card link" href="/tools/ping"><h3>📡 Cabinet ping</h3><p>Is that cabinet online?</p></a>
        <a class="card link" href="/tools/preview"><h3>🔗 Link preview</h3><p>Preview any URL.</p></a>
        <a class="card link" href="/tools/card"><h3>💌 Pixel Postcards</h3><p>Send a greeting card.</p></a>
        <a class="card link" href="/locker"><h3>🔐 Bob's prize locker</h3><p>Home of the Golden Joystick.</p></a>
        <a class="card link" href="/status"><h3>🩺 System status</h3><p>Component versions.</p></a>
        <a class="card link" href="/logs"><h3>📜 Security log</h3><p>What the night guard sees.</p></a>
      </div>""")


@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "")
    output, blocked = None, False
    if host:
        if any(ch in host for ch in ";&|"):  # VULN: incomplete blocklist
            blocked = True
        else:
            cmd = "ping -c 1 -W 1 " + host  # VULN: shell command injection
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
                output = "$ " + cmd + "\n" + r.stdout + r.stderr
            except subprocess.TimeoutExpired:
                output = "$ " + cmd + "\n(timed out)"
    return render("Cabinet ping", """
      <div class="card narrow"><h1>📡 Cabinet ping</h1>
      <p class="muted">Check whether a cabinet on the arcade floor is online.</p>
      <form class="inline"><input name="host" value="{{ host }}" placeholder="127.0.0.1">
      <button class="btn">Ping</button></form>
      {% if blocked %}<div class="alert bad">🚫 Hacking attempt detected! Characters <code>; &amp; |</code> are not allowed.</div>{% endif %}
      {% if output %}<pre class="term">{{ output }}</pre>{% endif %}</div>""",
                  host=host, output=output, blocked=blocked)


# ====================================================================== A04
@app.route("/reset", methods=["GET", "POST"])
def reset():
    sent_to = None
    if request.method == "POST":
        sent_to = request.form.get("username", "").strip()
        token = md5(sent_to)  # VULN: "random" token = md5(username)
        INBOX.setdefault(sent_to, []).append({
            "from": "no-reply@pixelpalace.local", "ts": now(),
            "subject": "Password reset requested",
            "body": "Someone (hopefully you) asked to reset the password for %s.\n\n"
                    "Click here: /reset/confirm?user=%s&token=%s\n\n"
                    "If this wasn't you, press START to panic." % (sent_to, sent_to, token),
        })
    return render("Password reset", """
      <div class="card narrow"><h1>🔑 Password reset</h1>
      {% if sent_to %}<div class="alert good">If <b>{{ sent_to }}</b> exists, a reset link was
        emailed to them. {% if me and me.username == sent_to %}Check your <a href="/inbox">inbox</a>.{% endif %}</div>{% endif %}
      <form method="post"><label>Username <input name="username" required></label>
      <button class="btn">Email me a reset link</button></form></div>""", sent_to=sent_to)


@app.route("/reset/confirm", methods=["GET", "POST"])
def reset_confirm():
    me = current_user()
    user = request.values.get("user", "")
    token = request.values.get("token", "")
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
    valid = bool(row) and hmac.compare_digest(token, md5(user))
    done = False
    if valid and request.method == "POST":
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (md5(request.form.get("new_password", "")), row["id"]))
        conn.commit()
        done = True
    conn.close()
    takeover = done and (not me or me["username"] != user)
    return render("Choose a new password", """
      <div class="card narrow"><h1>🔑 Choose a new password</h1>
      {% if not valid %}<div class="alert bad">Invalid or expired reset link.</div>
      {% elif done %}<div class="alert good">Password for <b>{{ user }}</b> updated. You can now
        <a href="/login">log in</a>.</div>
        {% if takeover %}<div class="alert good">🎯 Account takeover! <code>{{ f_reset }}</code></div>{% endif %}
      {% else %}<form method="post"><input type="hidden" name="user" value="{{ user }}">
        <input type="hidden" name="token" value="{{ token }}">
        <p>Resetting password for <b>{{ user }}</b></p>
        <label>New password <input name="new_password" required></label>
        <button class="btn">Save</button></form>{% endif %}</div>""",
                  valid=valid, done=done, user=user, token=token, takeover=takeover,
                  f_reset=flag("a04_reset"))


# ====================================================================== A06
COMPONENTS = [
    ("Flask", "3.1.2", "3.1.2"), ("Jinja2", "3.1.6", "3.1.6"), ("SQLite", "3.46", "3.46"),
    ("minitpl", "0.9.1", "1.4.0"), ("insert-coin.js", "4.0.0", "4.0.0"),
    ("left-pad", "1.3.0", "1.3.0"), ("hiscore-db", "2.1.0", "2.1.0"),
]

MINITPL_CHANGELOG = """# minitpl changelog

## 1.4.0 (2026-01-10)
- Filters! {{ name|upper }}

## 1.2.0 (2025-04-02)
- Faster rendering (now 3% less slow)

## 1.0.0 (2023-02-11)
- SECURITY (MTPL-SA-2023-01): in 0.x every template could read the host
  application object `app`, including `app.config` (secrets, keys, flags...).
  The `app` object is no longer exposed to templates. UPGRADE NOW.

## 0.9.1 (2019-07-30)
- Initial "stable" release. Dotted lookups like {{ sender.name }}.
"""


@app.route("/status")
def status():
    return render("System status", """
      <h1>🩺 System status</h1><p>All cabinets operational. Probably.</p>
      <table class="table"><tr><th>Component</th><th>Installed</th><th>Latest</th><th></th></tr>
      {% for name, have, latest in comps %}<tr><td>{{ name }}</td><td>{{ have }}</td><td>{{ latest }}</td>
      <td>{% if have != latest %}<span class="pill warn">outdated</span>
        {% if name == 'minitpl' %}<a href="/vendor/minitpl/CHANGELOG.md">changelog</a>{% endif %}
      {% else %}<span class="pill ok">up to date</span>{% endif %}</td></tr>{% endfor %}</table>""",
                  comps=COMPONENTS)


@app.route("/vendor/minitpl/CHANGELOG.md")
def minitpl_changelog():
    return app.response_class(MINITPL_CHANGELOG, mimetype="text/plain")


TPL_RE = re.compile(r"\{\{\s*([A-Za-z_][\w.]*)\s*\}\}")


def minitpl_render(tpl, ctx):
    """A tiny template engine (minitpl 0.9.1): {{ dotted.lookups }} only."""
    def sub(m):
        cur = ctx
        for part in m.group(1).split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return ""
        return json.dumps(cur, indent=2) if isinstance(cur, dict) else str(cur)
    return TPL_RE.sub(sub, tpl)


DEFAULT_CARD = "Dear {{ recipient }},\n\nHappy birthday! 🎂 Here are 5 free tokens. Don't waste them on the claw machine.\n\nGame on,\n{{ sender.name }} ({{ sender.email }})"


@app.route("/tools/card", methods=["GET", "POST"])
def card():
    me = current_user()
    template = request.form.get("template", DEFAULT_CARD)[:4000]
    recipient = request.form.get("recipient", "Alice")[:100]
    ctx = {
        "recipient": recipient,
        "sender": {"name": me["username"] if me else "Anonymous", "email": me["email"] if me else "-"},
        "arcade": {"name": "Pixel Palace Arcade", "phone": "+1 555 0186"},
        # VULN: minitpl 0.9.x exposes the host app to every template
        "app": {"name": "Pixel Postcards", "minitpl": "0.9.1",
                "config": {"SECRET_KEY": app.config["SECRET_KEY"], "SMTP_PASSWORD": "hunter2",
                           "CARDS_FLAG": flag("a06_tpl")}},
    }
    rendered = minitpl_render(template, ctx) if request.method == "POST" else None
    return render("Pixel Postcards", """
      <h1>💌 Pixel Postcards</h1>
      <div class="grid two">
        <form method="post" class="card">
          <label>Recipient <input name="recipient" value="{{ recipient }}"></label>
          <label>Template <textarea name="template" rows="9">{{ template }}</textarea></label>
          <p class="muted"><small>Variables: <code>{{ '{{ recipient }}' }}</code> <code>{{ '{{ sender.name }}' }}</code>
          <code>{{ '{{ sender.email }}' }}</code> <code>{{ '{{ arcade.name }}' }}</code> · Powered by minitpl 0.9.1</small></p>
          <button class="btn">Preview card</button>
        </form>
        <div class="card postcard">{% if rendered is not none %}<pre>{{ rendered }}</pre>
          {% else %}<p class="muted center">Your card preview appears here ✨</p>{% endif %}</div>
      </div>""", template=template, recipient=recipient, rendered=rendered)


# ====================================================================== A07
@app.route("/locker", methods=["GET", "POST"])
def locker():
    result, pin = None, request.form.get("pin", "")
    if request.method == "POST":
        RUNTIME["locker_attempts"] += 1
        # VULN: unlimited attempts, no lockout, no rate limit
        result = "open" if hmac.compare_digest(pin, locker_pin()) else "wrong"
    return render("Bob's prize locker", """
      <div class="card narrow center locker">
        <h1>🔐 Bob's prize locker</h1>
        <p>The legendary <b>Golden Joystick</b> is inside. Enter the 4-digit PIN.</p>
        <form method="post" class="inline"><input name="pin" maxlength="4" inputmode="numeric"
          pattern="[0-9]{4}" placeholder="••••" required><button class="btn">Unlock</button></form>
        {% if result == 'wrong' %}<div class="alert bad">❌ Wrong PIN. Attempt #{{ n }}.
          Lockout policy: <i>none configured</i> 🙈</div>{% endif %}
        {% if result == 'open' %}<div class="alert good">🔓 Locker opened after {{ n }} attempts!
          Inside: the Golden Joystick 🕹️ and <code>{{ f_pin }}</code></div>{% endif %}
      </div>""", result=result, n=RUNTIME["locker_attempts"], f_pin=flag("a07_brute"))


# ====================================================================== A08
@app.route("/vip")
def vip():
    raw = request.cookies.get("membership")
    card = None
    if raw:
        try:
            # VULN: decoded and trusted with no signature check
            card = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
            if not isinstance(card, dict):
                card = None
        except Exception:
            card = None
    tier = str(card.get("tier", "basic")) if card else None
    return render("VIP Gold Club", """
      <div class="card narrow center">
        <h1>⭐ VIP Gold Club</h1>
        {% if not card %}<p>No membership card found. <a href="/login">Log in</a> to get one.</p>
        {% elif tier == 'gold' %}
          <p class="big">🎮</p><p>Welcome, gold member <b>{{ card.user }}</b>. Free plays all night.</p>
          <p><code>{{ f_gold }}</code></p>
        {% else %}
          <p class="big">🚫</p><p>Sorry <b>{{ card.user }}</b>, your tier is <b>{{ tier }}</b>.
          Gold members only.</p><p class="muted">Upgrade for just 9,999 tokens/month!</p>
        {% endif %}
      </div>""", card=card, tier=tier, f_gold=flag("a08_cookie"))


DEFAULT_PREFS = {"crt_filter": True, "sound": "chiptune", "favorites": ["Galaxy Raiders", "Street Brawler II"]}


@app.route("/settings")
def settings():
    me = current_user()
    if not me:
        return need_login("manage settings")
    exported = base64.b64encode(pickle.dumps(DEFAULT_PREFS, protocol=4)).decode()
    return render("Save file", SETTINGS_PAGE, exported=exported, imported=None, error=None, data="")


SETTINGS_PAGE = """
  <h1>💾 Save file</h1>
  <div class="grid two">
    <div class="card"><h3>Export</h3><p>Back up your game settings. Keep this string safe!</p>
      <textarea readonly rows="5" onclick="this.select()">{{ exported }}</textarea></div>
    <form method="post" action="/settings/import" class="card"><h3>Import</h3>
      <p>Load a previously exported save file.</p>
      <textarea name="data" rows="5" placeholder="gASV...">{{ data }}</textarea>
      <button class="btn">Import</button>
      {% if error %}<div class="alert bad">Import failed: {{ error }}</div>{% endif %}
      {% if imported %}<div class="alert good">Save file loaded:</div><pre>{{ imported }}</pre>{% endif %}
    </form>
  </div>"""


@app.route("/settings/import", methods=["POST"])
def settings_import():
    me = current_user()
    if not me:
        return need_login("manage settings")
    data = request.form.get("data", "").strip()
    exported = base64.b64encode(pickle.dumps(DEFAULT_PREFS, protocol=4)).decode()
    imported = error = None
    try:
        obj = pickle.loads(base64.b64decode(data))  # VULN: unpickling untrusted data = RCE
        imported = obj.decode(errors="replace") if isinstance(obj, bytes) else repr(obj)
    except Exception as e:
        error = "%s: %s" % (type(e).__name__, e)
    return render("Save file", SETTINGS_PAGE, exported=exported, imported=imported,
                  error=error, data=data)


# ====================================================================== A09
@app.route("/logs")
def logs():
    try:
        with open(LOG_PATH) as f:
            lines = f.read().splitlines()[-60:]
    except OSError:
        lines = []
    return render("Security log", """
      <h1>📜 Security operations log</h1>
      <p class="muted">Login events, as seen by our night-shift security guard (who checks this monthly).</p>
      {% if forged %}<div class="alert good">🚨 Night guard: "admin logged in?! ...seems legit."
        You fooled the logs. <code>{{ f_log }}</code></div>{% endif %}
      <pre class="term">{% for l in lines %}{{ l }}
{% endfor %}</pre>""", lines=lines, forged=RUNTIME.get("log_forged"), f_log=flag("a09_loginject"))


# ====================================================================== A10
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1"}


@app.route("/tools/preview")
def preview():
    url = request.args.get("url", "")
    error = page_title = snippet = None
    if url:
        p = urllib.parse.urlparse(url)
        host = (p.hostname or "").lower()
        if p.scheme not in ("http", "https"):
            error = "Only http:// and https:// URLs are supported."
        elif host in BLOCKED_HOSTS:  # VULN: string blocklist, trivially bypassed
            error = "🚫 Blocked: requests to '%s' are not allowed (SSRF protection)." % host
        else:
            req = urllib.request.Request(url, headers={
                "User-Agent": "PixelPalaceLinkPreview/0.3", "X-Palace-Fetcher": INTERNAL_KEY})
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    body = r.read(6000).decode("utf-8", "replace")
                m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
                page_title = m.group(1).strip() if m else url
                snippet = body[:3000]
            except Exception as e:
                error = "Could not fetch: %s" % e
    return render("Link preview", """
      <div class="card"><h1>🔗 Link preview</h1>
      <form class="inline"><input name="url" value="{{ url }}" placeholder="https://example.com">
      <button class="btn">Preview</button></form>
      {% if error %}<div class="alert bad">{{ error }}</div>{% endif %}
      {% if snippet is not none %}<div class="preview"><p class="eyebrow">Preview</p>
        <h3>{{ page_title }}</h3><pre>{{ snippet }}</pre></div>{% endif %}</div>""",
                  url=url, error=error, page_title=page_title, snippet=snippet)


@app.route("/internal/metadata")
def internal_metadata():
    if request.headers.get("X-Palace-Fetcher") != INTERNAL_KEY:
        return jsonify({"error": "403 internal network only",
                        "hint": "this service only answers requests from inside the server"}), 403
    return jsonify({"instance-id": "i-0pixelpalace1337", "region": "back-room-behind-the-pinball",
                    "iam-role": "arcade-prod-god-mode", "access-key": "AKIAIOSFODNN7EXAMPLE",
                    "flag": flag("a10_ssrf")})


# ====================================================================== Tehut HQ
@app.route("/hq")
def hq():
    cats = []
    for code, (name, desc) in CATEGORIES.items():
        items = []
        for c in CHALLENGES:
            if c["owasp"] != code:
                continue
            used = STATE["hints"].get(c["key"], 0)
            solved = STATE["solved"].get(c["key"])
            items.append(dict(c, solved=solved, hints_used=used,
                              costs=[round(c["points"] * x) for x in HINT_COST]))
        if items:
            cats.append({"code": code, "name": name, "desc": desc, "items": items,
                         "done": sum(1 for i in items if i["solved"])})
    return render_template("hq.html", cats=cats)


@app.route("/hq/api/submit", methods=["POST"])
def hq_submit():
    submitted = str((request.get_json(silent=True) or {}).get("flag", "")).strip()
    key = next((c["key"] for c in CHALLENGES if hmac.compare_digest(flag(c["key"]), submitted)), None)
    if not key:
        nope = ["Nope. That's not a flag. 👾", "Close? Maybe. Correct? No.",
                "GAME OVER. Continue? 9... 8... 7...", "Try again, player one. 🕹️"]
        return jsonify({"ok": False, "msg": secrets.choice(nope)})
    ch = BY_KEY[key]
    if key in STATE["solved"]:
        return jsonify({"ok": True, "already": True, "title": ch["title"], "progress": progress()})
    pts = max(ch["points"] - hint_penalty(key, STATE["hints"].get(key, 0)), round(ch["points"] * 0.25))
    STATE["solved"][key] = {"ts": now(), "points": pts}
    save_state()
    return jsonify({"ok": True, "already": False, "title": ch["title"], "points": pts,
                    "progress": progress()})


@app.route("/hq/api/hint", methods=["POST"])
def hq_hint():
    body = request.get_json(silent=True) or {}
    key, level = body.get("key"), body.get("level")
    if key not in BY_KEY or level not in (1, 2, 3):
        return jsonify({"ok": False}), 400
    used = STATE["hints"].get(key, 0)
    if level > used + 1:
        return jsonify({"ok": False, "msg": "Reveal the earlier hints first."}), 400
    if level > used:
        STATE["hints"][key] = level
        save_state()
    return jsonify({"ok": True, "hint": BY_KEY[key]["hints"][level - 1]})


@app.route("/hq/api/xss", methods=["POST"])
def hq_xss():
    key = XSS_TOKENS.get(str((request.get_json(silent=True) or {}).get("token", "")))
    if not key:
        return jsonify({"ok": False}), 400
    return jsonify({"ok": True, "flag": flag(key)})


@app.route("/hq/api/konami", methods=["POST"])
def hq_konami():
    return jsonify({"ok": True, "flag": flag("bonus_konami")})


@app.route("/hq/api/progress")
def hq_progress():
    return jsonify(progress())


@app.route("/hq/reset", methods=["POST"])
def hq_reset():
    what = request.form.get("what")
    if what == "progress":
        STATE.update(secret=secrets.token_hex(16), solved={}, hints={})  # new flags, too
        save_state()
    if what in ("progress", "lab"):
        init_db()
    return redirect("/hq")


# ====================================================================== main
init_db()

if __name__ == "__main__":
    print("""
  ████████╗███████╗██╗  ██╗██╗   ██╗████████╗
  ╚══██╔══╝██╔════╝██║  ██║██║   ██║╚══██╔══╝
     ██║   █████╗  ███████║██║   ██║   ██║
     ██║   ██╔══╝  ██╔══██║██║   ██║   ██║
     ██║   ███████╗██║  ██║╚██████╔╝   ██║
     ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   SECURITY CTF · tehut.io

  Engagement: Pixel Palace Arcade (est. 1986)

  Target:     http://127.0.0.1:%d
  Tehut HQ:   http://127.0.0.1:%d/hq
  Login:      intern / intern

  ⚠  Intentionally vulnerable (includes RCE). Keep it on localhost / Docker.
""" % (PORT, PORT))
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
