import os, re, sys, time, html, json, secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from collections import defaultdict, deque
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session, render_template, Response
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, CodeReview, Finding
from analyzers import analyze_code, score, label, dedupe, ORDER, LANG_KEY, strip_line_numbers
from sqlalchemy import func
from services.ai_service import ai_review
from services.ai_client import configured, missing, provider, chat, AIError
from services.suggest_service import build_suggestion
from services.runner import run_code, enabled as exec_enabled
from services import toolchain
from parsing import engine_for
from services.report_pdf import build_pdf
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"), override=True)

hosted = lambda: bool(os.getenv("VERCEL") or os.getenv("RENDER"))   # Vercel / Render set these
production = lambda: hosted() or os.getenv("FLASK_ENV") == "production"

def db_url():
    """Postgres on Vercel (DATABASE_URL or POSTGRES_URL); SQLite file locally; temporary SQLite in /tmp if Vercel has no database yet."""
    url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
    if not url: return "sqlite:////tmp/codescan.db" if hosted() else "sqlite:///codescan.db"
    if url.startswith("postgres://"): url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):   # name the driver explicitly: newer SQLAlchemy defaults a bare postgresql:// to psycopg3, we ship psycopg2
        p = urlsplit(url); keep = [(k, v) for k, v in parse_qsl(p.query) if k in ("sslmode", "connect_timeout", "application_name")]   # drop params psycopg2 rejects (Supabase's supa=..., pgbouncer=...)
        url = urlunsplit(("postgresql+psycopg2", p.netloc, p.path, urlencode(keep), ""))
    return url

def secret_key():
    key = os.getenv("SECRET_KEY", "")
    if production() and (len(key) < 16 or key in ("change-this", "dev-only-change-me")):
        raise RuntimeError("Set a strong SECRET_KEY (16+ random characters) in the environment variables.")
    return key or "dev-only-change-me"

def migrate():
    """Add columns/indexes to databases created by older versions (create_all never alters existing tables)."""
    from sqlalchemy import inspect, text
    q = db.engine.dialect.identifier_preparer.quote("user"); cols = {c["name"] for c in inspect(db.engine).get_columns("user")}
    add = {"has_password": "BOOLEAN DEFAULT TRUE", "default_language": "VARCHAR(20)"}
    with db.engine.begin() as c:
        for n, t in add.items():
            if n not in cols: c.execute(text(f"ALTER TABLE {q} ADD COLUMN {n} {t}"))

def create_app(test_config=None):
    app = Flask(__name__, static_folder="public/static", static_url_path="/static")
    app.config.update(SECRET_KEY=secret_key(),
        SQLALCHEMY_DATABASE_URI=db_url(),
        MAX_CONTENT_LENGTH=512 * 1024, MAX_CODE_CHARS=int(os.getenv("MAX_CODE_CHARS", 200000)),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production(),
        SQLALCHEMY_ENGINE_OPTIONS={} if db_url().startswith("sqlite") else {"pool_pre_ping": True, "pool_recycle": 280})
    if test_config: app.config.update(test_config)
    if hosted(): app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)   # real client IP behind Vercel's proxy (rate limits)
    CORS(app, origins=os.getenv("CORS_ORIGINS", "http://127.0.0.1:5000").split(","), supports_credentials=True)
    db.init_app(app)
    with app.app_context():
        try: db.create_all(); migrate()
        except Exception as e:   # serverless cold starts can race on first table creation; locally fail loudly
            if not hosted(): raise
            app.logger.error("Database init: %s", e)

    hits = defaultdict(deque)
    def limited(key, n, per=60):
        q, t = hits[key], time.time()
        while q and q[0] < t - per: q.popleft()
        q.append(t); return len(q) > n

    def err(msg, code): return jsonify(success=False, error=msg), code

    @app.before_request
    def csrf_and_limit():
        if request.path.startswith("/api/"):
            if request.method in ("POST", "PUT", "DELETE") and request.headers.get("X-Requested-With") != "fetch":
                return err("Missing CSRF header.", 403)
            if limited((request.remote_addr, request.path.split("/")[2]), 60): return err("Too many requests.", 429)

    @app.after_request
    def headers(r):
        r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'"})
        if production(): r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return r

    @app.errorhandler(413)
    def too_big(e): return err("Submission is too large.", 413)
    @app.errorhandler(500)
    def server_err(e): return err("Unable to process the request.", 500)

    def login_required(f):
        @wraps(f)
        def w(*a, **k):
            if not session.get("uid"): return err("Authentication required.", 401)
            return f(*a, **k)
        return w

    @app.get("/")
    def index(): return render_template("index.html")
    @app.get("/api/health")
    def health(): return jsonify(success=True, status="ok")

    # ---- auth
    @app.post("/api/auth/register")
    def register():
        d = request.get_json(silent=True) or {}
        u, e, p = (d.get("username") or "").strip(), (d.get("email") or "").strip().lower(), d.get("password") or ""
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", u): return err("Username must be 3-30 letters, digits or underscores.", 422)
        if len(e) > 120 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e): return err("Invalid email address.", 422)
        if len(p) < 8 or not re.search(r"[A-Za-z]", p) or not re.search(r"\d", p): return err("Password needs 8+ characters with letters and digits.", 422)
        if p != d.get("confirm_password"): return err("Passwords do not match.", 422)
        if User.query.filter((User.username == u) | (User.email == e)).first(): return err("Username or email already in use.", 400)
        user = User(username=u, email=e, password_hash=generate_password_hash(p))
        db.session.add(user); db.session.commit()
        return jsonify(success=True), 201

    @app.post("/api/auth/login")
    def login():
        d = request.get_json(silent=True) or {}
        if limited(("login", request.remote_addr), 10): return err("Too many login attempts.", 429)
        ident = (d.get("identifier") or d.get("email") or "").strip().lower()
        user = User.query.filter((User.email == ident) | (func.lower(User.username) == ident)).first() if ident else None
        if not user or not check_password_hash(user.password_hash, d.get("password") or ""): return err("Invalid credentials.", 401)
        return login_user(user)

    @app.post("/api/auth/logout")
    def logout(): session.clear(); return jsonify(success=True)

    @app.get("/api/auth/me")
    @login_required
    def me():
        u = db.session.get(User, session["uid"])
        return jsonify(success=True, user=user_dict(u))

    # ---- accounts: password reset (email code) and settings
    def user_dict(u):
        return dict(username=u.username, email=u.email, default_language=u.default_language or "python", has_password=bool(u.has_password), created_at=u.created_at.isoformat())
    def login_user(u): session.clear(); session["uid"] = u.id; return jsonify(success=True, user=user_dict(u))
    def pw_error(p):
        return None if len(p or "") >= 8 and re.search(r"[A-Za-z]", p) and re.search(r"\d", p) else "Password needs 8+ characters with letters and digits."
    def current(): return db.session.get(User, session["uid"])

    @app.get("/api/settings")
    @login_required
    def get_settings():
        u = current()
        return jsonify(success=True, user=user_dict(u), total_reviews=CodeReview.query.filter_by(user_id=u.id).count())

    @app.put("/api/settings")
    @login_required
    def save_settings():
        d, u = request.get_json(silent=True) or {}, current()
        if "username" in d:
            name = (d["username"] or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", name): return err("Username must be 3-30 letters, digits or underscores.", 422)
            if User.query.filter(func.lower(User.username) == name.lower(), User.id != u.id).first(): return err("Username already in use.", 400)
            u.username = name
        if "default_language" in d:
            if d["default_language"] not in LANG_KEY: return err("Unsupported language.", 422)
            u.default_language = d["default_language"]
        db.session.commit(); return jsonify(success=True, user=user_dict(u))

    @app.put("/api/settings/password")
    @login_required
    def change_password():
        d, u = request.get_json(silent=True) or {}, current()
        if u.has_password and not check_password_hash(u.password_hash, d.get("current_password") or ""): return err("Current password is wrong.", 401)
        e = pw_error(d.get("new_password"))
        if e: return err(e, 422)
        u.password_hash = generate_password_hash(d["new_password"]); u.has_password = True; db.session.commit()
        return jsonify(success=True)

    @app.delete("/api/reviews")
    @login_required
    def delete_all_reviews():
        for r in CodeReview.query.filter_by(user_id=session["uid"]).all(): db.session.delete(r)
        db.session.commit(); return jsonify(success=True)

    @app.delete("/api/account")
    @login_required
    def delete_account():
        d, u = request.get_json(silent=True) or {}, current()
        if d.get("confirm") != "DELETE": return err("Type DELETE to confirm.", 422)
        if u.has_password and not check_password_hash(u.password_hash, d.get("password") or ""): return err("Wrong password.", 401)
        for r in CodeReview.query.filter_by(user_id=u.id).all(): db.session.delete(r)
        db.session.delete(u); db.session.commit(); session.clear()
        return jsonify(success=True)

    # ---- analysis
    def run_analysis(d):
        lang, src = (d.get("language") or "").lower(), d.get("code")
        if not isinstance(src, str) or not src.strip(): raise ValueError("Please enter source code before starting the review.")
        if lang not in LANG_KEY: raise ValueError("Unsupported language.")
        if len(src) > app.config["MAX_CODE_CHARS"]: raise ValueError(f"Code exceeds the {app.config['MAX_CODE_CHARS']} character limit.")
        src, note = strip_line_numbers(src.replace("\r\n", "\n"))
        t0, dbg = time.time(), {}
        found = analyze_code(lang, src, dbg)
        summary, ai, status = ai_review(lang, src, [f["title"] for f in found])
        status = (status + f" Syntax engine: {engine_for(lang)}.")[:200]
        found = dedupe(found + ai)
        sc = score(found)
        if not summary: summary = f"{len(found)} issue(s) found. Rating: {label(sc['overall'])}." if found else "No issues detected by the enabled analyzers."
        if note: summary = note + " " + summary
        dbg["line_numbers_removed"] = bool(note)
        dbg.update(language=lang, engine=engine_for(lang), analysis_ms=int((time.time() - t0) * 1000), findings=len(found), ai=status,
                   by_source={k: sum(1 for f in found if f["source"] == k) for k in {f["source"] for f in found}},
                   syntax_errors=sum(1 for f in found if f["title"] == "Syntax error" or f["title"].startswith("Compiler error")))
        return dict(language=lang, summary=summary, ai_status=status, scores=sc, rating=label(sc["overall"]), findings=found, debug=dbg, code=src)

    @app.post("/api/analyze")
    @login_required
    def analyze():
        try: return jsonify(success=True, **run_analysis(request.get_json(silent=True) or {}))
        except ValueError as e: return err(str(e), 422)
        except Exception as e: app.logger.exception("analysis failed"); return err("Unable to analyze the submitted code.", 500)

    def review_dict(r, full=False):
        fs = r.findings
        top = max((f.severity for f in fs), key=ORDER.index, default="NONE")
        d = dict(id=r.id, language=r.language, overall_score=r.overall_score, security_score=r.security_score,
                 quality_score=r.quality_score, maintainability_score=r.maintainability_score, reliability_score=r.reliability_score,
                 issue_count=len(fs), highest_severity=top, summary=r.summary, ai_status=r.ai_status, created_at=r.created_at.isoformat())
        if full: d.update(source_code=r.source_code, findings=[f.to_dict() for f in sorted(fs, key=lambda f: (-ORDER.index(f.severity), f.line_number or 0))])
        return d

    def owned(rid):
        r = db.session.get(CodeReview, rid)
        return r if r and r.user_id == session["uid"] else None   # 404 for others' reviews: no existence leak

    @app.post("/api/reviews")
    @login_required
    def create_review():
        try: res = run_analysis(request.get_json(silent=True) or {})
        except ValueError as e: return err(str(e), 422)
        except Exception: app.logger.exception("analysis failed"); return err("Unable to analyze the submitted code.", 500)
        s = res["scores"]
        r = CodeReview(user_id=session["uid"], language=res["language"], source_code=res["code"], overall_score=s["overall"],
            security_score=s["security"], quality_score=s["quality"], maintainability_score=s["maintainability"],
            reliability_score=s["reliability"], summary=res["summary"], ai_status=res["ai_status"])
        r.findings = [Finding(**{k: f[k] for k in Finding.FIELDS}) for f in res["findings"]]
        db.session.add(r); db.session.commit()
        return jsonify(success=True, review=review_dict(r, True), rating=res["rating"], debug=res["debug"]), 201

    @app.get("/api/reviews")
    @login_required
    def list_reviews():
        rs = CodeReview.query.filter_by(user_id=session["uid"]).order_by(CodeReview.created_at.desc()).all()
        return jsonify(success=True, reviews=[review_dict(r) for r in rs])

    @app.get("/api/reviews/<int:rid>")
    @login_required
    def get_review(rid):
        r = owned(rid)
        return jsonify(success=True, review=review_dict(r, True)) if r else err("Review not found.", 404)

    @app.delete("/api/reviews/<int:rid>")
    @login_required
    def delete_review(rid):
        r = owned(rid)
        if not r: return err("Review not found.", 404)
        db.session.delete(r); db.session.commit(); return jsonify(success=True)

    @app.get("/api/reviews/<int:rid>/report")
    @login_required
    def report(rid):
        r = owned(rid)
        if not r: return err("Review not found.", 404)
        d = review_dict(r, True)
        return Response(build_pdf(d, current().username), mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=codescan-report-{rid}.pdf"})
    @app.get("/api/ai/status")
    @login_required
    def ai_status():
        ok = configured()
        return jsonify(success=True, configured=ok, missing=missing(), model=os.getenv("AI_MODEL", "") if ok else "", provider=provider())

    @app.post("/api/ai/test")
    @login_required
    def ai_test():
        if limited(("aitest", session["uid"]), 5): return err("Too many tests. Wait a minute.", 429)
        try: chat("Reply with the single word OK.", max_tokens=20, timeout=30)
        except AIError as e: return err(str(e), 502)
        return jsonify(success=True, message="AI connection works.")

    @app.get("/api/dashboard")
    @login_required
    def dashboard():
        rs = CodeReview.query.filter_by(user_id=session["uid"]).order_by(CodeReview.created_at.desc()).all()
        sev, langs = {s: 0 for s in reversed(ORDER)}, {}
        for r in rs:
            langs[r.language] = langs.get(r.language, 0) + 1
            for f in r.findings: sev[f.severity] = sev.get(f.severity, 0) + 1
        sc = [r.overall_score for r in rs if r.overall_score is not None]
        return jsonify(success=True, total=len(rs), avg_score=round(sum(sc) / len(sc)) if sc else None, best_score=max(sc) if sc else None,
                       issues=sum(sev.values()), severity=sev, languages=langs, recent=[review_dict(r) for r in rs[:5]])

    @app.get("/api/reviews/<int:rid>/suggestion")
    @login_required
    def suggestion(rid):
        r = owned(rid)
        if not r: return err("Review not found.", 404)
        try: return jsonify(success=True, **build_suggestion(r.language, r.source_code, [f.to_dict() for f in r.findings]))
        except Exception: app.logger.exception("suggestion failed"); return err("Unable to build suggested code.", 500)

    @app.get("/api/debug/status")
    @login_required
    def debug_status():
        try: langs = toolchain.status()
        except Exception: app.logger.exception("status failed"); return err("Unable to read toolchain status.", 500)
        return jsonify(success=True, hosted=hosted(), execution_enabled=exec_enabled(), compiler_checks=toolchain.checks_enabled(), python=sys.version.split()[0], languages=langs)

    @app.post("/api/run")
    @login_required
    def run():
        d = request.get_json(silent=True) or {}
        lang, code = (d.get("language") or "").lower(), d.get("code")
        if lang not in LANG_KEY or not isinstance(code, str) or not code.strip(): return err("Language and code are required.", 422)
        if len(code) > app.config["MAX_CODE_CHARS"]: return err("Code is too large.", 422)
        if limited(("run", session["uid"]), 8): return err("Too many runs. Wait a minute.", 429)
        try: return jsonify(success=True, **run_code(lang, strip_line_numbers(code.replace("\r\n", "\n"))[0]))
        except Exception: app.logger.exception("run failed"); return err("Unable to run the code.", 500)

    return app

app = create_app()   # Vercel (and gunicorn / flask run) look for this top-level variable

if __name__ == "__main__":
    debug = (os.getenv("FLASK_DEBUG") or ("0" if production() else "1")).lower() in ("1", "true", "on")   # local runs print "Debug mode: on"
    app.run(debug=debug)
