# Security policy

**This project is intentionally vulnerable.** It is a training lab, and every challenge in
it is a deliberate security bug. Please don't report those: SQL injection, XSS, command
injection, insecure deserialization, SSRF and the rest are the point of the game.

## How to run it safely

- Run it on your own machine, in Docker (recommended) or a throwaway VM.
- Keep it bound to `127.0.0.1` (the default). Never expose it to a network or the internet.
- Some challenges give remote code execution on whatever runs the app. Treat it like malware
  you are studying.

## What we *do* want to hear about

The lab has guard rails that protect the player's own machine while it runs. Please report:

- A way for **another website** to reach the lab through the player's browser (bypassing the
  cross-site request and DNS-rebinding protection).
- A way to reach the lab from the network when it runs with the default settings.
- A challenge flag that shows up **without** exploiting the intended bug.
- A challenge that can't be solved.

## Reporting

Open a GitHub issue for unsolvable challenges or leaked flags. For a guard-rail bypass,
please report it privately (GitHub → Security → *Report a vulnerability*) or contact
[Tehut Security](https://tehut.io).
