"""Challenge catalogue for the Tehut Security CTF (https://tehut.io): Pixel Palace Arcade.

Each challenge has a story ("brief"), three progressively stronger hints and a
"lesson" that is revealed once it is solved. Flags are NOT stored here: they
are derived per-install from a random secret (see app.flag()), so reading the
source on GitHub doesn't hand out the answers.

Adding a challenge: append a dict below, then make some page in app.py show
flag("<your key>") when the vulnerability is exploited.
"""

# Fraction of a challenge's points each hint costs (hint 1, 2, 3).
HINT_COST = (0.10, 0.20, 0.30)

CATEGORIES = {
    "A01": ("Broken Access Control", "Users acting outside of their intended permissions."),
    "A02": ("Cryptographic Failures", "Weak or missing protection of sensitive data."),
    "A03": ("Injection", "Untrusted data interpreted as code: SQL, HTML/JS, shell."),
    "A04": ("Insecure Design", "Flaws baked into the design, not just the code."),
    "A05": ("Security Misconfiguration", "Debug modes, defaults, verbose errors."),
    "A06": ("Vulnerable & Outdated Components", "Running libraries with known holes."),
    "A07": ("Identification & Authentication Failures", "Weak sessions, brute-forceable logins."),
    "A08": ("Software & Data Integrity Failures", "Trusting data that nobody signed."),
    "A09": ("Security Logging & Monitoring Failures", "Logs you can't trust, alerts that never fire."),
    "A10": ("Server-Side Request Forgery", "Making the server fetch things for you."),
    "BONUS": ("Bonus", "Secrets for the curious."),
}

CHALLENGES = [
    # ------------------------------------------------------------------ A01
    {
        "key": "a01_idor", "owasp": "A01", "slug": "n0sy_n31ghb0ur",
        "title": "Nosy Neighbour", "difficulty": "easy", "points": 100,
        "entry": "/profile",
        "brief": "Log in as the intern and open your staff profile. Alice from the prize "
                 "counter keeps something juicy in her private notes. Read them.",
        "hints": [
            "Look closely at the URL of your own profile page.",
            "The <code>id</code> parameter is just a number. Who decides which numbers you may use?",
            "While logged in as intern, open <code>/profile?id=2</code>.",
        ],
        "lesson": "<b>Insecure Direct Object Reference.</b> The server trusted the id in the URL "
                  "and never checked that the record belongs to you. Fix: authorize every object "
                  "access on the server (<code>if row.owner != current_user: 403</code>).",
    },
    {
        "key": "a01_api", "owasp": "A01", "slug": "f0rg0tt3n_4p1",
        "title": "Forgotten API", "difficulty": "easy", "points": 150,
        "entry": "/admin",
        "brief": "The admin console says <i>Staff only</i>. Good! But the console's backend "
                 "was built in a hurry. Search engines were told to stay away from a few paths...",
        "hints": [
            "Every website has a file telling crawlers where <i>not</i> to look.",
            "<code>/robots.txt</code> lists an API path. Protecting the page isn't the same as protecting the API.",
            "Open <code>/api/v1/admin/users</code>.",
        ],
        "lesson": "Hiding a link or protecting only the HTML page isn't access control. Every "
                  "endpoint, especially APIs, must enforce authorization. And robots.txt is public: "
                  "never list secret paths in it.",
    },
    {
        "key": "a01_csrf", "owasp": "A01", "slug": "m4n4g3r_cl1cks_3v3ryth1ng",
        "title": "Manager Clicks Everything", "difficulty": "medium", "points": 250,
        "entry": "/support",
        "brief": "The floor manager (admin) is always logged in and reads every help desk message, "
                 "loading every image and following every link. Token gifts are plain GET requests. "
                 "Make the manager gift <b>you</b> tokens.",
        "hints": [
            "Gift some tokens yourself and look at the URL the form produces.",
            "No CSRF token and it's a GET. If the manager's browser loads that URL, the gift is sent <i>as the manager</i>.",
            "Send the manager: <code>&lt;img src=\"/gift?to=intern&amp;amount=1000\"&gt;</code>",
        ],
        "lesson": "<b>Cross-Site Request Forgery.</b> Browsers attach the victim's cookies "
                  "automatically. State-changing actions must never use GET, and must require an "
                  "anti-CSRF token. <code>SameSite=Lax/Strict</code> cookies are a strong extra layer.",
    },
    # ------------------------------------------------------------------ A02
    {
        "key": "a02_crack", "owasp": "A02", "slug": "b4ckup_blund3r",
        "title": "Backup Blunder", "difficulty": "medium", "points": 200,
        "entry": "/",
        "brief": "Rumour says Bob the technician left a database backup on the web server. The "
                 "passwords in it are \"encrypted\", he swears. Log in as the arcade's <b>owner</b> "
                 "and read their secret memo on the account page.",
        "hints": [
            "The same file that leaked the API also mentions backups.",
            "32 hex characters, no salt: that's plain MD5. Try crackstation.net, or hashcat with rockyou.txt.",
            "The owner's hash cracks to a top-20 rockyou password: <code>hashcat -m 0 &lt;hash&gt; rockyou.txt</code>",
        ],
        "lesson": "Fast unsalted hashes (MD5, SHA-1) are not password storage: billions of "
                  "guesses per second and precomputed tables crack them instantly. Use Argon2id, "
                  "bcrypt or scrypt. And never keep backups in the web root.",
    },
    # ------------------------------------------------------------------ A03
    {
        "key": "a03_sqli", "owasp": "A03", "slug": "un10n_st4t10n",
        "title": "Union Station", "difficulty": "medium", "points": 250,
        "entry": "/search",
        "brief": "The arcade news search is backed by SQLite. Rumour has it the database "
                 "holds a table of secrets that has nothing to do with news.",
        "hints": [
            "Search for a single quote <code>'</code> and read the error carefully.",
            "The query returns 3 columns. <code>UNION SELECT</code> appends your own rows. SQLite keeps its schema in <code>sqlite_master</code>.",
            "<code>' UNION SELECT 1,name,sql FROM sqlite_master--</code> then <code>' UNION SELECT id,label,secret FROM cheat_codes--</code>",
        ],
        "lesson": "Building SQL with string concatenation lets input become code. Use "
                  "parameterized queries (<code>?</code> placeholders) everywhere, and never show "
                  "raw database errors to users.",
    },
    {
        "key": "a03_xss_reflected", "owasp": "A03", "slug": "m1rr0r_m1rr0r",
        "title": "Mirror, Mirror", "difficulty": "easy", "points": 100,
        "entry": "/hello?name=intern",
        "brief": "Game over, new high score! The leaderboard screen shows whatever name you "
                 "enter, exactly as typed. Pop an <code>alert()</code> to prove you can run JavaScript.",
        "hints": [
            "Change the <code>name</code> parameter in the URL to some HTML, like <code>&lt;b&gt;hi&lt;/b&gt;</code>.",
            "If HTML renders, a <code>&lt;script&gt;</code> tag probably runs too.",
            "<code>/hello?name=&lt;script&gt;alert(1)&lt;/script&gt;</code>",
        ],
        "lesson": "<b>Reflected XSS.</b> Input was placed into HTML without encoding. Fix: "
                  "context-aware output encoding (keep template auto-escaping on!) plus a "
                  "Content-Security-Policy as a safety net.",
    },
    {
        "key": "a03_xss_stored", "owasp": "A03", "slug": "gr4ff1t1_w4ll",
        "title": "Graffiti Wall", "difficulty": "medium", "points": 200,
        "entry": "/comments",
        "brief": "The graffiti wall keeps every tag forever. Security added a filter that strips "
                 "<code>&lt;script&gt;</code> tags. Surely that's enough? Make an "
                 "<code>alert()</code> fire for everyone who visits.",
        "hints": [
            "Post a <code>&lt;script&gt;</code> tag and look at what's left of it.",
            "JavaScript also runs from event-handler attributes, not just script tags.",
            "<code>&lt;img src=x onerror=alert(1)&gt;</code>",
        ],
        "lesson": "Blocklists always miss something. Encode output by default; if you really need "
                  "user HTML, use a vetted allowlist sanitizer (DOMPurify, nh3). Stored XSS hits "
                  "every visitor, admins included.",
    },
    {
        "key": "a03_cmd", "owasp": "A03", "slug": "p1ng_0f_d00m",
        "title": "Ping of Doom", "difficulty": "medium", "points": 250,
        "entry": "/tools/ping",
        "brief": "The cabinet ping tool checks if an arcade machine is online, and blocks <code>;</code> <code>&amp;</code> "
                 "and <code>|</code> to stay safe. The flag sits in a file on the server: "
                 "<code>data/secrets/ping_flag.txt</code>.",
        "hints": [
            "Your input ends up in a shell command: <code>ping -c 1 -W 1 &lt;host&gt;</code>.",
            "Shells have other ways to run commands: a newline (<code>%0a</code> in the URL) or command substitution <code>$(...)</code>.",
            "<code>/tools/ping?host=$(cat data/secrets/ping_flag.txt)</code> and read the error message.",
        ],
        "lesson": "Never build shell commands from user input. Pass an argument list without a "
                  "shell (<code>subprocess.run(['ping', '-c', '1', host])</code>) and validate input "
                  "against an allowlist (for example, a strict IP regex).",
    },
    # ------------------------------------------------------------------ A04
    {
        "key": "a04_reset", "owasp": "A04", "slug": "r3s3t_r0ul3tt3",
        "title": "Reset Roulette", "difficulty": "medium", "points": 200,
        "entry": "/reset",
        "brief": "Forgot your password? Pixel Palace emails you a reset link. Request one for "
                 "yourself, study it, then take over <b>someone else's</b> account.",
        "hints": [
            "Request a reset for <code>intern</code>, then check your <a href='/inbox'>inbox</a>.",
            "The token is 32 hex characters, so it's probably MD5. MD5 of what? Try your username.",
            "token = md5(username): <code>echo -n alice | md5sum</code> → <code>/reset/confirm?user=alice&amp;token=&lt;hash&gt;</code>",
        ],
        "lesson": "Reset tokens must be random and unguessable (<code>secrets.token_urlsafe(32)</code>), "
                  "single-use and short-lived. A design flaw like this survives any amount of code "
                  "polishing, so threat-model your flows.",
    },
    {
        "key": "a04_logic", "owasp": "A04", "slug": "1nf1n1t3_t0k3n_gl1tch",
        "title": "Infinite Token Glitch", "difficulty": "easy", "points": 150,
        "entry": "/gift",
        "brief": "You start with 100 tokens. Become a <b>token tycoon</b> (1,000,000+ tokens) "
                 "using nothing but the token gifting feature.",
        "hints": [
            "The form won't let you type a negative number. Who says you have to use the form?",
            "What happens to <i>your</i> balance if you gift someone -1000 tokens?",
            "<code>/gift?to=admin&amp;amount=-1000000</code>",
        ],
        "lesson": "Client-side validation is a UX feature, not security. The server must enforce "
                  "every business rule: positive amounts, limits, ownership.",
    },
    # ------------------------------------------------------------------ A05
    {
        "key": "a05_debug", "owasp": "A05", "slug": "st4ck_tr4c3_sp1ll",
        "title": "Stack Trace Spill", "difficulty": "easy", "points": 100,
        "entry": "/profile",
        "brief": "Production is running with debug mode <b>ON</b>. Make the app crash and it "
                 "will tell you far more than it should.",
        "hints": [
            "Feed a page input it doesn't expect.",
            "Your profile URL takes a numeric <code>id</code>. What if it isn't a number?",
            "<code>/profile?id=banana</code>",
        ],
        "lesson": "Turn debug off in production, show generic error pages and log details "
                  "server-side only. Verbose errors hand attackers paths, versions and secrets.",
    },
    # ------------------------------------------------------------------ A06
    {
        "key": "a06_tpl", "owasp": "A06", "slug": "4nc13nt_t3mpl4t3s",
        "title": "Ancient Templates", "difficulty": "medium", "points": 200,
        "entry": "/tools/card",
        "brief": "Pixel Postcards sends greeting cards using a templating library. The "
                 "<a href='/status'>status page</a> lists component versions. One is ancient, "
                 "and its changelog tells you everything.",
        "hints": [
            "Open <code>/status</code> and find the component that's far behind its latest version.",
            "Read minitpl's changelog. The 1.0.0 release fixed something templates could access.",
            "Put <code>{{ app.config }}</code> in your card template.",
        ],
        "lesson": "Know your dependencies (an SBOM, <code>pip-audit</code>, Dependabot) and patch them. "
                  "Public advisories for known-vulnerable components get exploited within hours.",
    },
    # ------------------------------------------------------------------ A07
    {
        "key": "a07_session", "owasp": "A07", "slug": "c00k13_f0rg3ry",
        "title": "Cookie Forgery", "difficulty": "medium", "points": 200,
        "entry": "/session",
        "brief": "The floor manager (admin) is logged in somewhere right now. Session IDs look random... are "
                 "they? Become the admin without knowing their password.",
        "hints": [
            "Log in as intern and inspect your <code>sessid</code> cookie on <code>/session</code>.",
            "It's 32 hex characters. Compare it to <code>md5('intern')</code>.",
            "Set the cookie <code>sessid</code> to md5('admin') = <code>21232f297a57a5a743894a0e4a801fc3</code> and open <code>/account</code>.",
        ],
        "lesson": "Session IDs must be long random values from a CSPRNG, rotated on login and "
                  "invalidated on logout. Use your framework's session management; don't invent one.",
    },
    {
        "key": "a07_brute", "owasp": "A07", "slug": "p1n_cr4ck3r",
        "title": "PIN Cracker", "difficulty": "hard", "points": 300,
        "entry": "/locker",
        "brief": "Bob's prize locker holds the legendary Golden Joystick, protected by a 4-digit "
                 "PIN. No lockout, no CAPTCHA, no rate limit. Only 10,000 possibilities, so automate it.",
        "hints": [
            "Submit one wrong PIN and look at the request: method, URL, field name.",
            "Write a loop: Python, Burp Intruder, ffuf, or a bash loop with curl.",
            "<code>for i in range(10000): r = requests.post(URL, data={'pin': f'{i:04d}'}); if 'FLAG{' in r.text: print(i)</code>",
        ],
        "lesson": "Rate-limit and lock out after repeated failures, add MFA, and alert on "
                  "brute-force patterns. Short secrets are only safe with strict attempt limits.",
    },
    # ------------------------------------------------------------------ A08
    {
        "key": "a08_cookie", "owasp": "A08", "slug": "g0ld_m3mb3rsh1p",
        "title": "Gold Membership", "difficulty": "easy", "points": 150,
        "entry": "/vip",
        "brief": "The VIP Gold Club (free plays all night!) is gold tier only. Your tier is "
                 "stored... in your own browser? Interesting.",
        "hints": [
            "DevTools → Application/Storage → Cookies. Look at <code>membership</code>.",
            "It's base64-encoded JSON, and nothing signs it.",
            "Decode it, change <code>\"tier\": \"basic\"</code> to <code>\"gold\"</code>, re-encode it, overwrite the cookie and reload.",
        ],
        "lesson": "Never trust client-side data for authorization. If state must live on the "
                  "client, sign it (HMAC, a properly verified JWT), or keep it server-side.",
    },
    {
        "key": "a08_pickle", "owasp": "A08", "slug": "p1ckl3_r1ck",
        "title": "Pickle Rick", "difficulty": "hard", "points": 400,
        "entry": "/settings",
        "brief": "You can export and import your game save file. The export looks like "
                 "base64 gibberish. The flag is in a file on the server: "
                 "<code>data/secrets/pickle_flag.txt</code>.",
        "hints": [
            "Export your save file and base64-decode it. Recognize the format? Python folks know <code>gASV</code>...",
            "It's a Python <b>pickle</b>. Unpickling can call any function via <code>__reduce__</code>.",
            "<code>class P:<br>&nbsp;def __reduce__(self): return (subprocess.check_output, (['cat','data/secrets/pickle_flag.txt'],))<br>print(base64.b64encode(pickle.dumps(P())).decode())</code>",
        ],
        "lesson": "Never deserialize untrusted data with pickle (or Java serialization, or "
                  "<code>yaml.load</code>). It's remote code execution by design. Use JSON with schema "
                  "validation, and sign anything that leaves your server.",
    },
    # ------------------------------------------------------------------ A09
    {
        "key": "a09_loginject", "owasp": "A09", "slug": "f4k3_n3ws_l0gs",
        "title": "Fake News Logs", "difficulty": "hard", "points": 300,
        "entry": "/logs",
        "brief": "The night-shift guard watches the login log on <code>/logs</code>. Failed logins record the "
                 "username you typed, verbatim. Forge a log entry saying <b>admin logged in "
                 "successfully</b>.",
        "hints": [
            "Fail a login, then look at the line that appears in <code>/logs</code>.",
            "What if your username contains a newline (<code>%0a</code>)? A browser form won't send one; curl or Burp will.",
            "<code>curl --data 'username=x%0a2026-01-01 00:00:00 LOGIN SUCCESS user=admin&amp;password=x' http://127.0.0.1:5000/login</code>",
        ],
        "lesson": "Logs are evidence. Neutralize CR/LF before logging, prefer structured (JSON) "
                  "logs, and protect log integrity. A09 is about logs you can trust and alerts "
                  "that actually fire.",
    },
    # ------------------------------------------------------------------ A10
    {
        "key": "a10_ssrf", "owasp": "A10", "slug": "1ns1d3_j0b",
        "title": "Inside Job", "difficulty": "hard", "points": 350,
        "entry": "/tools/preview",
        "brief": "The link-preview tool fetches any URL, from the <i>server's</i> point of view. "
                 "An internal metadata service at <code>/internal/metadata</code> only answers "
                 "internal requests. And <code>localhost</code>/<code>127.0.0.1</code> are blocked...",
        "hints": [
            "Try previewing <code>http://127.0.0.1:5000/internal/metadata</code>. Blocked. The filter compares the hostname <i>as text</i>.",
            "There are many ways to spell 127.0.0.1: <code>127.1</code>, <code>0.0.0.0</code>, <code>2130706433</code>, <code>0x7f000001</code>...",
            "<code>/tools/preview?url=http://127.1:5000/internal/metadata</code>",
        ],
        "lesson": "With SSRF the server becomes your proxy into the internal network (in the cloud, "
                  "the metadata service hands out credentials!). Allowlist destinations, resolve DNS "
                  "and reject private IPs <i>after</i> resolution, disable redirects, segment networks.",
    },
    # ------------------------------------------------------------------ BONUS
    {
        "key": "bonus_konami", "owasp": "BONUS", "slug": "up_up_d0wn_d0wn",
        "title": "Old School", "difficulty": "easy", "points": 50,
        "entry": "/hq",
        "brief": "This is an arcade. Some codes never die, and gamers of a certain age know this one by heart.",
        "hints": [
            "It's a famous cheat code from 1986.",
            "↑ ↑ ↓ ↓ ← → ← → ...",
            "↑ ↑ ↓ ↓ ← → ← → B A, typed on any page.",
        ],
        "lesson": "Not every flag is a vulnerability. Sometimes it's just fun. 🎮",
    },
]

BY_KEY = {c["key"]: c for c in CHALLENGES}

RANKS = [
    (0.00, "Button Masher", "🕹️"),
    (0.10, "Coin-Op Rookie", "🪙"),
    (0.30, "Combo Breaker", "🥊"),
    (0.55, "Boss Fighter", "⚔️"),
    (0.80, "High Score Legend", "🏆"),
    (1.00, "Pixel Palace's Final Boss", "👑"),
]


def rank_for(fraction):
    current = RANKS[0]
    for r in RANKS:
        if fraction + 1e-9 >= r[0]:
            current = r
    return {"name": current[1], "icon": current[2]}
