"""Пароль менеджері: Flask веб-қосымшасы."""
import os
import secrets
import sqlite3
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (Flask, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)

import crypto

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vault.db")
SECRET_PATH = os.path.join(BASE_DIR, "secret.key")


def load_secret_key() -> bytes:
    """Flask сессия кілтін бір рет жасап, файлда сақтайды."""
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(SECRET_PATH, "rb") as f:
        return f.read()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

ph = PasswordHasher()
# Шифрлау кілттері тек сервердің жадында тұрады (cookie-ге жазылмайды).
KEYS: dict[str, bytes] = {}


# ---------- Дерекқор ----------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            salt BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            url TEXT,
            username TEXT,
            password_enc TEXT NOT NULL,
            notes_enc TEXT
        );
        """
    )
    db.commit()
    db.close()


# ---------- Қауіпсіздік көмекшілері ----------
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "CSRF токені қате")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session or session.get("sid") not in KEYS:
            session.clear()
            flash("Алдымен жүйеге кіріңіз.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_key() -> bytes:
    return KEYS[session["sid"]]


def get_entry_or_404(entry_id: int) -> sqlite3.Row:
    row = get_db().execute(
        "SELECT * FROM entries WHERE id = ? AND user_id = ?",
        (entry_id, session["user_id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return row


# ---------- Тіркелу / кіру ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(username) < 3:
            flash("Логин кемінде 3 таңбадан тұруы керек.", "error")
        elif len(password) < 10:
            flash("Master пароль кемінде 10 таңба болуы керек.", "error")
        elif password != confirm:
            flash("Парольдер сәйкес келмейді.", "error")
        else:
            try:
                get_db().execute(
                    "INSERT INTO users (username, pw_hash, salt) VALUES (?, ?, ?)",
                    (username, ph.hash(password), crypto.new_salt()),
                )
                get_db().commit()
                flash("Тіркелу сәтті. Енді кіріңіз.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Бұл логин бос емес.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        ok = False
        if user:
            try:
                ph.verify(user["pw_hash"], password)
                ok = True
            except VerifyMismatchError:
                pass
        if ok:
            old_sid = session.get("sid")
            if old_sid:
                KEYS.pop(old_sid, None)
            session.clear()
            sid = secrets.token_hex(32)
            KEYS[sid] = crypto.derive_key(password, user["salt"])
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["sid"] = sid
            return redirect(url_for("dashboard"))
        flash("Логин немесе пароль қате.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    KEYS.pop(session.get("sid"), None)
    session.clear()
    return redirect(url_for("login"))


# ---------- Парольдер ----------
@app.route("/")
@login_required
def dashboard():
    rows = get_db().execute(
        "SELECT id, title, url, username FROM entries WHERE user_id = ? "
        "ORDER BY title COLLATE NOCASE",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", entries=rows)


def read_form():
    return {
        "title": request.form.get("title", "").strip(),
        "url": request.form.get("url", "").strip(),
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", ""),
        "notes": request.form.get("notes", ""),
    }


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        f = read_form()
        if not f["title"] or not f["password"]:
            flash("Атауы мен парольді толтырыңыз.", "error")
            return render_template("form.html", entry=f, mode="add")
        key = current_key()
        get_db().execute(
            "INSERT INTO entries (user_id, title, url, username, password_enc, notes_enc) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session["user_id"], f["title"], f["url"], f["username"],
             crypto.encrypt(key, f["password"]),
             crypto.encrypt(key, f["notes"]) if f["notes"] else None),
        )
        get_db().commit()
        flash("Пароль сақталды.", "ok")
        return redirect(url_for("dashboard"))
    return render_template("form.html", entry={}, mode="add")


@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit(entry_id):
    row = get_entry_or_404(entry_id)
    key = current_key()
    if request.method == "POST":
        f = read_form()
        if not f["title"]:
            flash("Атауын толтырыңыз.", "error")
            return render_template("form.html", entry=f, mode="edit", entry_id=entry_id)
        # Пароль өрісі бос болса, ескі пароль сақталады.
        pw_enc = crypto.encrypt(key, f["password"]) if f["password"] else row["password_enc"]
        get_db().execute(
            "UPDATE entries SET title=?, url=?, username=?, password_enc=?, notes_enc=? "
            "WHERE id=? AND user_id=?",
            (f["title"], f["url"], f["username"], pw_enc,
             crypto.encrypt(key, f["notes"]) if f["notes"] else None,
             entry_id, session["user_id"]),
        )
        get_db().commit()
        flash("Өзгерістер сақталды.", "ok")
        return redirect(url_for("dashboard"))
    entry = {
        "title": row["title"], "url": row["url"], "username": row["username"],
        "password": "",
        "notes": crypto.decrypt(key, row["notes_enc"]) if row["notes_enc"] else "",
    }
    return render_template("form.html", entry=entry, mode="edit", entry_id=entry_id)


@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id):
    get_entry_or_404(entry_id)
    get_db().execute(
        "DELETE FROM entries WHERE id=? AND user_id=?", (entry_id, session["user_id"])
    )
    get_db().commit()
    flash("Жазба жойылды.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/reveal/<int:entry_id>", methods=["POST"])
@login_required
def reveal(entry_id):
    row = get_entry_or_404(entry_id)
    return jsonify(password=crypto.decrypt(current_key(), row["password_enc"]))


init_db()

if __name__ == "__main__":
    app.run(debug=False)
