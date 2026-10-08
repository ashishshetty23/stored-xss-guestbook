# Stored XSS CTF — "The Guestbook" (easy)

A deliberately vulnerable guestbook. Comments are **stored** in SQLite and
rendered back to the page **without escaping**, so submitted HTML/JavaScript
is persisted and executed in every visitor's browser — textbook
**stored (persistent) XSS**.

An **admin bot** (headless Chromium via Playwright) opens any comment you
"Report to admin". If your stored payload runs JavaScript in the admin's
browser (any `alert` / `confirm` / `prompt` dialog), the bot rewards you with
the flag.

---

## Challenge flow (for players)

1. Sign the guestbook with a message.
2. On the message's permalink page, click **Report to admin**.
3. The admin bot opens your message. If your JS runs, the result page shows the flag.

### Intended solution

Put any of these in the **Message** field, submit, then report it:

```html
<script>alert(1)</script>
```

```html
<img src=x onerror=alert(1)>
```

```html
<svg onload=alert(document.domain)>
```

That's it — getting JS to fire proves the stored XSS. The flag appears on the
report result page.

---

## Run locally

```bash
cd stored-xss-guestbook
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install --with-deps chromium   # one-time: fetch the browser
python app.py
# open http://127.0.0.1:5000
```

## Deploy on Render

This needs the **Docker** runtime (the admin bot requires a real browser), so
deploy as a Docker web service:

1. Push this folder to a GitHub repo.
2. In Render: **New → Web Service**, connect the repo.
   - Render auto-detects `render.yaml` (Blueprint) — just confirm.
   - Or manually: Runtime **Docker**, it will use the `Dockerfile`.
3. Set the **`FLAG`** environment variable to your real flag (edit it in
   `render.yaml` or the dashboard). Then deploy.
4. Share the Render URL with players.

The bot runs inside the same container and reaches the app over `127.0.0.1`,
so no extra config is needed. On Render's free plan the service sleeps when
idle and the first request after a nap is slow — fine for a CTF.

### Config (environment variables)

| Var          | Default                            | Purpose                                  |
|--------------|------------------------------------|------------------------------------------|
| `FLAG`       | `CTF{st0red_xss_pops_the_admin}`   | The flag handed out on a successful XSS. |
| `BOT_WAIT_MS`| `2500`                             | How long the bot waits for your JS.      |
| `DB_PATH`    | `/tmp/guestbook.db`                | SQLite file location.                    |

> The SQLite DB lives in `/tmp`, so it resets on redeploy/restart. That's
> usually what you want for a CTF (a fresh board).

---

## How the vulnerability works

- **Source:** the `body` field of a submitted comment (`/post`).
- **Sink:** `{{ c.body | safe }}` in `templates/index.html` and
  `templates/view.html` — `|safe` disables Jinja2's auto-escaping, so the raw
  comment is written straight into the HTML.
- **Impact:** persisted script runs in the context of anyone who views the
  page, including the admin bot.

**The fix** (what you'd tell players in a writeup): remove `|safe` and let
Jinja2 auto-escape, or sanitize with an allowlist (e.g. `bleach`) before
storing/rendering. Add a Content-Security-Policy as defense-in-depth.

> ⚠️ This app is intentionally insecure. Don't run it alongside anything you
> care about, and don't put real secrets in the container.
