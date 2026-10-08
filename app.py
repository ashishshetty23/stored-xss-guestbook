"""
Stored XSS CTF — "Guestbook"
----------------------------
An intentionally vulnerable guestbook. Comments are stored in SQLite and
rendered to the page WITHOUT escaping (the `|safe` filter in the templates),
so any HTML/JS a visitor submits is stored and later executed in every other
visitor's browser — classic stored (persistent) XSS.

Win condition: prove your stored payload runs in the *admin's* browser.
Click "Report to admin" on your comment. A headless-Chromium "admin bot"
then opens that comment. If your payload fires any JS dialog
(alert/confirm/prompt), the bot hands you the flag on the result page.

This is a teaching target. Do not deploy it as a real public service with
anything sensitive behind it.
"""

import os
import sqlite3
import threading
import queue
import secrets

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    abort,
)

# --- Config (override via environment variables on Render) -----------------
FLAG = os.environ.get("FLAG", "CTF{st0red_xss_pops_the_admin}")
DB_PATH = os.environ.get("DB_PATH", "/tmp/guestbook.db")
PORT = os.environ.get("PORT", "5000")
# The admin bot runs inside this same container, so it visits over localhost.
BASE_URL = os.environ.get("BASE_URL", f"http://127.0.0.1:{PORT}")
# How long the bot waits for your JS to run, in milliseconds.
BOT_WAIT_MS = int(os.environ.get("BOT_WAIT_MS", "2500"))

app = Flask(__name__)

# --- Database --------------------------------------------------------------
_db_lock = threading.Lock()


def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock:
        conn = db()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS comments(
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                name    TEXT NOT NULL,
                body    TEXT NOT NULL,
                created TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS reports(
                id         TEXT PRIMARY KEY,
                comment_id INTEGER NOT NULL,
                status     TEXT NOT NULL,
                flag       TEXT
            );
            """
        )
        conn.commit()
        conn.close()


def set_report(rid, status, flag=None):
    with _db_lock:
        conn = db()
        conn.execute(
            "UPDATE reports SET status=?, flag=? WHERE id=?", (status, flag, rid)
        )
        conn.commit()
        conn.close()


# --- Admin bot (headless Chromium) -----------------------------------------
bot_q: "queue.Queue[tuple[str, int]]" = queue.Queue()


def bot_worker():
    """Consume report jobs and visit each comment as the 'admin'."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        while True:
            rid, cid = bot_q.get()
            try:
                ctx = browser.new_context()
                page = ctx.new_page()

                fired = {"hit": False}

                def on_dialog(dialog):
                    fired["hit"] = True
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)
                page.goto(
                    f"{BASE_URL}/view/{cid}",
                    wait_until="load",
                    timeout=15000,
                )
                page.wait_for_timeout(BOT_WAIT_MS)
                ctx.close()

                if fired["hit"]:
                    set_report(rid, "solved", FLAG)
                else:
                    set_report(rid, "no-xss", None)
            except Exception as exc:  # keep the worker alive no matter what
                set_report(rid, f"error: {exc}", None)
            finally:
                bot_q.task_done()


_started = False
_start_lock = threading.Lock()


def ensure_started():
    global _started
    with _start_lock:
        if not _started:
            init_db()
            threading.Thread(target=bot_worker, daemon=True).start()
            _started = True


# Start on import so it works under gunicorn too (use a single worker).
ensure_started()


# --- Routes ----------------------------------------------------------------
@app.route("/")
def index():
    conn = db()
    rows = conn.execute(
        "SELECT * FROM comments ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return render_template("index.html", comments=rows)


@app.route("/post", methods=["POST"])
def post():
    name = (request.form.get("name") or "anonymous").strip()[:60]
    body = (request.form.get("body") or "").strip()[:2000]
    if not body:
        return redirect(url_for("index"))
    conn = db()
    cur = conn.execute(
        "INSERT INTO comments(name, body) VALUES(?, ?)", (name, body)
    )
    conn.commit()
    cid = cur.lastrowid
    conn.close()
    return redirect(url_for("view", cid=cid))


@app.route("/view/<int:cid>")
def view(cid):
    conn = db()
    row = conn.execute("SELECT * FROM comments WHERE id=?", (cid,)).fetchone()
    conn.close()
    if not row:
        abort(404)
    return render_template("view.html", c=row)


@app.route("/report/<int:cid>", methods=["POST"])
def report(cid):
    conn = db()
    row = conn.execute(
        "SELECT id FROM comments WHERE id=?", (cid,)
    ).fetchone()
    conn.close()
    if not row:
        abort(404)
    rid = secrets.token_urlsafe(12)
    with _db_lock:
        conn = db()
        conn.execute(
            "INSERT INTO reports(id, comment_id, status) VALUES(?, ?, ?)",
            (rid, cid, "pending"),
        )
        conn.commit()
        conn.close()
    bot_q.put((rid, cid))
    return redirect(url_for("result", rid=rid))


@app.route("/result/<rid>")
def result(rid):
    conn = db()
    row = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    conn.close()
    if not row:
        abort(404)
    return render_template("result.html", r=row)


@app.route("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    # Local dev server. In production Render runs gunicorn (see Dockerfile).
    app.run(host="0.0.0.0", port=int(PORT), threaded=True)
