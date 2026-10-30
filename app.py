"""ফেসবুক বিজনেস ম্যানেজমেন্ট প্ল্যাটফর্ম — ধাপ ১
লগইন, কর্মচারী অ্যাকাউন্ট, client যোগ, ১ client = ১ Page সংযোগ।
"""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from meta import validate_page_token
from security import Crypto, RateLimiter
from store import AlreadyExists, FirestoreStore, MemoryStore, now_iso

ORDER_MODES = {
    "ai_orders": "AI অর্ডার নেবে (কর্মচারী দেখবে ও নিশ্চিত করবে)",
    "phone_only": "শুধু ফোন নম্বর দেবে (কাস্টমার client-কে কল করে অর্ডার করবে)",
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PAGE_ID_RE = re.compile(r"^\d{5,30}$")
PHONE_RE = re.compile(r"^[0-9+\-\s()]{6,20}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{20,200}$")
DHAKA = timezone(timedelta(hours=6))


def staff_id_for(email):
    """ইমেইল থেকে নির্দিষ্ট আইডি। একই ইমেইলে দুইবার অ্যাকাউন্ট খোলা যায় না।"""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:32]


def create_app(overrides=None):
    app = Flask(__name__)
    cfg = {
        "SECRET_KEY": os.environ.get("SECRET_KEY", ""),
        "ENCRYPTION_KEY": os.environ.get("ENCRYPTION_KEY", ""),
        "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", ""),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", ""),
        "BASE_URL": os.environ.get("BASE_URL", ""),
        "META_GRAPH_API_VERSION": os.environ.get("META_GRAPH_API_VERSION", "v26.0"),
        "FIREBASE_SERVICE_ACCOUNT_JSON": os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", ""),
        "ALLOW_MEMORY_STORE": os.environ.get("ALLOW_MEMORY_STORE", ""),
    }
    cfg.update(overrides or {})

    # ---- শুরুতেই কনফিগারেশন যাচাই। ভুল থাকলে অ্যাপ চালুই হবে না ----
    problems = []
    if len(cfg["SECRET_KEY"]) < 32:
        problems.append("SECRET_KEY অন্তত ৩২ অক্ষরের হতে হবে")
    crypto = None
    try:
        crypto = Crypto(cfg["ENCRYPTION_KEY"])
    except Exception:
        problems.append("ENCRYPTION_KEY ঠিক নেই (README-তে বানানোর কমান্ড দেওয়া আছে)")
    if not cfg["ADMIN_USERNAME"]:
        problems.append("ADMIN_USERNAME দেওয়া নেই")
    if len(cfg["ADMIN_PASSWORD"]) < 10:
        problems.append("ADMIN_PASSWORD অন্তত ১০ অক্ষরের হতে হবে")
    store = cfg.get("STORE")
    if store is None:
        sa = cfg["FIREBASE_SERVICE_ACCOUNT_JSON"]
        if sa:
            try:
                store = FirestoreStore(json.loads(sa))
            except Exception as e:
                problems.append("Firebase-এ সংযোগ করা যায়নি (" + type(e).__name__ + ")")
        elif str(cfg["ALLOW_MEMORY_STORE"]).lower() in ("1", "true", "yes"):
            store = MemoryStore()
        else:
            problems.append("FIREBASE_SERVICE_ACCOUNT_JSON দেওয়া নেই")
    if problems:
        raise RuntimeError("কনফিগারেশনে সমস্যা:\n- " + "\n- ".join(problems))

    app.config.update(
        SECRET_KEY=cfg["SECRET_KEY"],
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg["BASE_URL"].startswith("https://"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=1_000_000,
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.store, app.crypto = store, crypto
    logging.basicConfig(level=logging.INFO)

    limiter = RateLimiter()
    dummy_hash = generate_password_hash("dummy-password-for-timing")
    admin_user = cfg["ADMIN_USERNAME"].strip().lower()
    admin_pass = cfg["ADMIN_PASSWORD"]
    graph_version = cfg["META_GRAPH_API_VERSION"]

    # ---------------- সাহায্যকারী ----------------
    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    def current_user():
        role = session.get("role")
        if role == "admin":
            return {"role": "admin", "name": "Admin", "assigned": []}
        if role == "staff":
            s = store.get("staff", session.get("staff_id", ""))
            if s and s.get("active"):
                return {"role": "staff", "name": s["name"], "id": s["id"], "email": s["email"],
                        "assigned": s.get("assigned_client_ids", [])}
        return None

    def actor_label():
        return "admin" if g.user["role"] == "admin" else g.user["email"]

    def audit(action, client_id=None, detail=""):
        """সংবেদনশীল কাজের রেকর্ড। এখানে কখনো token বা key লেখা হয় না।"""
        try:
            store.add("audit_logs", {"ts": now_iso(), "actor": actor_label(), "action": action,
                                     "client_id": client_id, "detail": detail[:300]})
        except Exception:
            app.logger.exception("audit log লেখা যায়নি")

    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not g.user:
                return redirect(url_for("login"))
            return f(*a, **kw)
        return wrapper

    def admin_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not g.user:
                return redirect(url_for("login"))
            if g.user["role"] != "admin":
                abort(403)
            return f(*a, **kw)
        return wrapper

    def load_client(client_id):
        """কর্মচারী শুধু নিজের বরাদ্দ করা, সক্রিয় client দেখতে পাবে। বাকিদের জন্য 'নেই' বলা হয়।"""
        c = store.get("clients", client_id)
        if not c:
            abort(404)
        if g.user["role"] == "admin":
            return c
        if client_id in g.user["assigned"] and c.get("status") == "active":
            return c
        abort(404)

    def clean_text(name, maxlen):
        return (request.form.get(name) or "").strip()[:maxlen]

    # ---------------- নিরাপত্তা ----------------
    @app.before_request
    def protect():
        if request.endpoint == "static":
            return
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token", "")
            expected = session.get("_csrf")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400)
        g.user = current_user()

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if g.get("user"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token, "user": g.get("user"),
                "memory_mode": store.kind == "memory", "ORDER_MODES": ORDER_MODES}

    @app.template_filter("dt")
    def fmt_dt(value):
        try:
            return datetime.fromisoformat(value).astimezone(DHAKA).strftime("%Y-%m-%d %H:%M")
        except (TypeError, ValueError):
            return "—"

    for code, msg in ((400, "অনুরোধটি ঠিক ছিল না। পাতা রিফ্রেশ করে আবার চেষ্টা করুন।"),
                      (403, "এই পাতা দেখার অনুমতি আপনার নেই।"),
                      (404, "পাতাটি পাওয়া যায়নি।"),
                      (413, "ফাইল বা লেখা অনেক বড়।"),
                      (500, "সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন।")):
        app.register_error_handler(code, lambda e, code=code, msg=msg: (
            render_template("error.html", code=code, message=msg), code))

    # ---------------- লগইন ----------------
    def authenticate(ident, pw):
        if (hmac.compare_digest(ident.encode(), admin_user.encode())
                and hmac.compare_digest(pw.encode(), admin_pass.encode())):
            return {"role": "admin"}
        doc = store.get("staff", staff_id_for(ident)) if "@" in ident else None
        ok = check_password_hash(doc["password_hash"] if doc else dummy_hash, pw)
        if doc and ok and doc.get("active"):
            return {"role": "staff", "staff_id": doc["id"]}
        return None

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/health")
    def health():
        return jsonify(ok=True, store=store.kind)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            ident = clean_text("identifier", 120).lower()
            pw = (request.form.get("password") or "")[:200]
            key = f"{request.remote_addr}|{ident}"
            if limiter.blocked(key):
                flash("অনেকবার ভুল হয়েছে। ১৫ মিনিট পরে আবার চেষ্টা করুন।", "error")
                return render_template("login.html"), 429
            who = authenticate(ident, pw)
            if who:
                limiter.reset(key)
                session.clear()  # নতুন সেশন, পুরনোটা বাতিল
                session.permanent = True
                session.update(who)
                csrf_token()
                return redirect(url_for("dashboard"))
            limiter.fail(key)
            flash("ইমেইল বা পাসওয়ার্ড ঠিক নয়।", "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------------- ড্যাশবোর্ড ----------------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        if g.user["role"] == "admin":
            clients = store.list("clients")
            staff = store.list("staff")
            assigned = {cid for s in staff if s.get("active") for cid in s.get("assigned_client_ids", [])}
            active = [c for c in clients if c.get("status") == "active"]
            stats = {"clients": len(clients), "active": len(active),
                     "suspended": len(clients) - len(active), "staff": len(staff),
                     "unassigned": len([c for c in active if c["id"] not in assigned])}
            return render_template("dashboard_admin.html", stats=stats)
        mine = [store.get("clients", cid) for cid in g.user["assigned"]]
        mine = sorted([c for c in mine if c and c.get("status") == "active"], key=lambda c: c["name"])
        return render_template("dashboard_staff.html", clients=mine)

    # ---------------- কর্মচারী (শুধু Admin) ----------------
    def read_staff_form(editing=False):
        name = clean_text("name", 80)
        pw = (request.form.get("password") or "")[:200]
        errors = []
        if not name:
            errors.append("নাম দিন।")
        if pw or not editing:
            if len(pw) < 8:
                errors.append("পাসওয়ার্ড অন্তত ৮ অক্ষরের হতে হবে।")
        valid = {c["id"] for c in store.list("clients")}
        picked = [i for i in request.form.getlist("clients") if i in valid]
        return name, pw, picked, errors

    @app.route("/admin/staff")
    @admin_required
    def staff_list():
        names = {c["id"]: c["name"] for c in store.list("clients")}
        rows = sorted(store.list("staff"), key=lambda s: s["name"])
        for s in rows:
            s["client_names"] = [names[i] for i in s.get("assigned_client_ids", []) if i in names]
        return render_template("staff_list.html", rows=rows)

    @app.route("/admin/staff/new", methods=["GET", "POST"])
    @admin_required
    def staff_new():
        clients = sorted(store.list("clients"), key=lambda c: c["name"])
        if request.method == "POST":
            name, pw, picked, errors = read_staff_form()
            email = clean_text("email", 120).lower()
            if not EMAIL_RE.match(email):
                errors.append("সঠিক ইমেইল দিন।")
            if not errors:
                sid = staff_id_for(email)
                try:
                    store.create("staff", sid, {"name": name, "email": email, "active": True,
                                                "password_hash": generate_password_hash(pw),
                                                "assigned_client_ids": picked, "created_at": now_iso()})
                except AlreadyExists:
                    errors.append("এই ইমেইলে আগেই অ্যাকাউন্ট আছে।")
                else:
                    audit("staff_created", detail=email)
                    flash("কর্মচারীর অ্যাকাউন্ট তৈরি হয়েছে।", "ok")
                    return redirect(url_for("staff_list"))
            for e in errors:
                flash(e, "error")
        return render_template("staff_form.html", staff=None, clients=clients, form=request.form)

    @app.route("/admin/staff/<sid>", methods=["GET", "POST"])
    @admin_required
    def staff_edit(sid):
        s = store.get("staff", sid)
        if not s:
            abort(404)
        clients = sorted(store.list("clients"), key=lambda c: c["name"])
        if request.method == "POST":
            name, pw, picked, errors = read_staff_form(editing=True)
            if not errors:
                upd = {"name": name, "active": request.form.get("active") == "on",
                       "assigned_client_ids": picked}
                if pw:
                    upd["password_hash"] = generate_password_hash(pw)
                store.update("staff", sid, upd)
                audit("staff_updated", detail=s["email"] + (" (পাসওয়ার্ড বদল)" if pw else ""))
                flash("সংরক্ষণ হয়েছে।", "ok")
                return redirect(url_for("staff_list"))
            for e in errors:
                flash(e, "error")
        return render_template("staff_form.html", staff=s, clients=clients, form=request.form)

    # ---------------- client ----------------
    @app.route("/clients")
    @login_required
    def clients_list():
        if g.user["role"] == "admin":
            rows = sorted(store.list("clients"), key=lambda c: c["name"])
            staff = store.list("staff")
            for c in rows:
                c["staff_names"] = [s["name"] for s in staff
                                    if s.get("active") and c["id"] in s.get("assigned_client_ids", [])]
        else:
            rows = [store.get("clients", cid) for cid in g.user["assigned"]]
            rows = sorted([c for c in rows if c and c.get("status") == "active"], key=lambda c: c["name"])
        return render_template("clients.html", rows=rows)

    def read_settings_form(is_admin):
        """ফোন, অর্ডারের ধরন, নির্দেশ। Admin হলে নাম ও Gemini key-ও।"""
        errors = []
        out = {
            "phone": clean_text("phone", 20),
            "order_mode": request.form.get("order_mode", ""),
            "custom_instructions": clean_text("custom_instructions", 5000),
        }
        if out["order_mode"] not in ORDER_MODES:
            errors.append("অর্ডার নেওয়ার ধরন বেছে নিন।")
        if out["phone"] and not PHONE_RE.match(out["phone"]):
            errors.append("ফোন নম্বর ঠিক নেই।")
        if out["order_mode"] == "phone_only" and not out["phone"]:
            errors.append("'শুধু ফোন নম্বর দেবে' বেছে নিলে client-এর ফোন নম্বর দিতে হবে।")
        if is_admin:
            out["name"] = clean_text("name", 80)
            if not out["name"]:
                errors.append("client-এর নাম দিন।")
            key = clean_text("gemini_key", 200)
            if key and not KEY_RE.match(key):
                errors.append("Gemini key ঠিক নেই।")
            out["_gemini_key"] = key
            out["_clear_key"] = request.form.get("clear_gemini_key") == "on"
        return out, errors

    @app.route("/admin/clients/new", methods=["GET", "POST"])
    @admin_required
    def client_new():
        if request.method == "POST":
            f, errors = read_settings_form(True)
            page_id = clean_text("page_id", 30)
            token = clean_text("page_token", 1000)
            if not PAGE_ID_RE.match(page_id):
                errors.append("Page ID শুধু সংখ্যা হবে।")
            if not token:
                errors.append("Page Access Token দিন।")
            page_name = ""
            if not errors:
                ok, page_name, err = validate_page_token(page_id, token, graph_version)
                if not ok:
                    errors.append(err)
            if not errors:
                cid = uuid.uuid4().hex
                try:
                    # Page আইডি আগে দখল করা হয়। একই Page দুই client-এ যেতে পারে না।
                    store.create("pages", page_id, {"client_id": cid, "created_at": now_iso()})
                except AlreadyExists:
                    errors.append("এই Page আগেই আরেকটি client-এ যুক্ত আছে।")
                else:
                    try:
                        doc = {"name": f["name"], "page_id": page_id, "page_name": page_name,
                               "page_token_enc": app.crypto.encrypt(token), "phone": f["phone"],
                               "order_mode": f["order_mode"],
                               "custom_instructions": f["custom_instructions"],
                               "gemini_key_enc": app.crypto.encrypt(f["_gemini_key"]) if f["_gemini_key"] else "",
                               "status": "active", "integration_status": "connected",
                               "validated_at": now_iso(), "created_at": now_iso()}
                        store.create("clients", cid, doc)
                    except Exception:
                        store.delete("pages", page_id)
                        app.logger.exception("client তৈরি ব্যর্থ")
                        abort(500)
                    audit("client_created", cid, f"page_id={page_id}")
                    flash("client যোগ হয়েছে। Facebook টোকেন যাচাই হয়েছে।", "ok")
                    return redirect(url_for("client_view", client_id=cid))
            for e in errors:
                flash(e, "error")
        return render_template("client_new.html", form=request.form)

    @app.route("/clients/<client_id>")
    @login_required
    def client_view(client_id):
        c = load_client(client_id)
        staff_names = []
        if g.user["role"] == "admin":
            staff_names = [s["name"] for s in store.list("staff")
                           if s.get("active") and client_id in s.get("assigned_client_ids", [])]
        return render_template("client_view.html", c=c, staff_names=staff_names)

    @app.route("/clients/<client_id>/settings", methods=["GET", "POST"])
    @login_required
    def client_settings(client_id):
        c = load_client(client_id)
        is_admin = g.user["role"] == "admin"
        if request.method == "POST":
            f, errors = read_settings_form(is_admin)
            if not errors:
                upd = {k: f[k] for k in ("phone", "order_mode", "custom_instructions")}
                changed = [k for k in upd if upd[k] != c.get(k)]
                if is_admin:
                    if f["name"] != c["name"]:
                        upd["name"] = f["name"]
                        changed.append("name")
                    if f["_gemini_key"]:
                        upd["gemini_key_enc"] = app.crypto.encrypt(f["_gemini_key"])
                        changed.append("gemini_key")
                    elif f["_clear_key"] and c.get("gemini_key_enc"):
                        upd["gemini_key_enc"] = ""
                        changed.append("gemini_key_removed")
                store.update("clients", client_id, upd)
                audit("client_settings_updated", client_id, "বদলেছে: " + ", ".join(changed or ["কিছু না"]))
                flash("সংরক্ষণ হয়েছে।", "ok")
                return redirect(url_for("client_view", client_id=client_id))
            for e in errors:
                flash(e, "error")
        return render_template("client_settings.html", c=c, form=request.form)

    @app.post("/admin/clients/<client_id>/status")
    @admin_required
    def client_status(client_id):
        c = store.get("clients", client_id)
        if not c:
            abort(404)
        new = "suspended" if request.form.get("to") == "suspended" else "active"
        store.update("clients", client_id, {"status": new})
        audit("client_" + new, client_id)
        flash("client স্থগিত করা হয়েছে। ডেটা মোছা হয়নি।" if new == "suspended" else "client আবার চালু হয়েছে।", "ok")
        return redirect(url_for("client_view", client_id=client_id))

    @app.route("/admin/clients/<client_id>/page", methods=["GET", "POST"])
    @admin_required
    def client_page(client_id):
        """Page বদলানো বা টোকেন নবায়ন। নতুন Page-এর টোকেন আগে Facebook-এ যাচাই হয়।"""
        c = store.get("clients", client_id)
        if not c:
            abort(404)
        if request.method == "POST":
            page_id = clean_text("page_id", 30)
            token = clean_text("page_token", 1000)
            errors = []
            if not PAGE_ID_RE.match(page_id):
                errors.append("Page ID শুধু সংখ্যা হবে।")
            if not token:
                errors.append("Page Access Token দিন।")
            changing = page_id != c["page_id"]
            if changing and request.form.get("confirm") != "on":
                errors.append("Page বদলাতে চাইলে নিশ্চিত করার ঘরে টিক দিন।")
            if not errors:
                ok, page_name, err = validate_page_token(page_id, token, graph_version)
                if not ok:
                    errors.append(err)
            if not errors and changing:
                try:
                    store.create("pages", page_id, {"client_id": client_id, "created_at": now_iso()})
                except AlreadyExists:
                    errors.append("এই Page আগেই আরেকটি client-এ যুক্ত আছে।")
            if not errors:
                store.update("clients", client_id, {
                    "page_id": page_id, "page_name": page_name,
                    "page_token_enc": app.crypto.encrypt(token),
                    "integration_status": "connected", "validated_at": now_iso()})
                if changing:
                    store.delete("pages", c["page_id"])
                    audit("page_replaced", client_id, f"{c['page_id']} -> {page_id}")
                else:
                    audit("page_token_renewed", client_id, f"page_id={page_id}")
                flash("Page সংযোগ হালনাগাদ হয়েছে। টোকেন যাচাই হয়েছে।", "ok")
                return redirect(url_for("client_view", client_id=client_id))
            for e in errors:
                flash(e, "error")
        return render_template("client_page.html", c=c, form=request.form)

    @app.route("/admin/audit")
    @admin_required
    def audit_view():
        rows = sorted(store.list("audit_logs"), key=lambda r: r["ts"], reverse=True)[:100]
        names = {c["id"]: c["name"] for c in store.list("clients")}
        for r in rows:
            r["client_name"] = names.get(r.get("client_id"), "")
        return render_template("audit.html", rows=rows)

    return app
