import pytest
from app import create_app
H = {"X-Requested-With": "fetch"}
PW = "Passw0rd123"

@pytest.fixture
def client():
    return create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"}).test_client()

def signup(c, name):
    r = c.post("/api/auth/register", json=dict(username=name, email=f"{name}@x.com", password=PW, confirm_password=PW), headers=H)
    assert r.status_code == 201
    return c.post("/api/auth/login", json=dict(email=f"{name}@x.com", password=PW), headers=H)

def test_auth_flow(client):
    assert signup(client, "alice").status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    client.post("/api/auth/logout", headers=H)
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json=dict(email="alice@x.com", password="bad"), headers=H).status_code == 401

def test_password_hashed(client):
    from models import User
    signup(client, "bob")
    with client.application.app_context(): assert User.query.first().password_hash != PW

def test_empty_and_findings(client):
    signup(client, "carol")
    assert client.post("/api/analyze", json=dict(language="python", code="  "), headers=H).status_code == 422
    code = 'password = "admin123"\ndef f(x=[]):\n    try:\n        eval(x)\n    except:\n        pass\n'
    d = client.post("/api/analyze", json=dict(language="python", code=code), headers=H).get_json()
    titles = {f["title"] for f in d["findings"]}
    assert {"Hardcoded credential", "Mutable default argument", "Bare except"} <= titles
    clean = client.post("/api/analyze", json=dict(language="python", code="x = 1\n"), headers=H).get_json()
    assert clean["findings"] == [] and clean["scores"]["overall"] == 100

def test_syntax_error(client):
    signup(client, "dan")
    d = client.post("/api/analyze", json=dict(language="python", code="def f(:\n"), headers=H).get_json()
    assert d["findings"][0]["title"] == "Syntax error"

def test_review_isolation(client):
    signup(client, "eve")
    rid = client.post("/api/reviews", json=dict(language="javascript", code="var a = eval(x);"), headers=H).get_json()["review"]["id"]
    client.post("/api/auth/logout", headers=H)
    signup(client, "mallory")
    assert client.get(f"/api/reviews/{rid}").status_code == 404

def test_new_languages_and_username_login(client):
    signup(client, "hank")
    client.post("/api/auth/logout", headers=H)
    assert client.post("/api/auth/login", json=dict(identifier="HANK", password=PW), headers=H).status_code == 200
    d = client.post("/api/analyze", json=dict(language="php", code="<?php eval($_GET['x']);"), headers=H).get_json()
    assert any("eval" in f["title"].lower() for f in d["findings"])
    d = client.post("/api/analyze", json=dict(language="c", code="char b[8]; gets(b);"), headers=H).get_json()
    assert d["findings"][0]["severity"] == "CRITICAL"

def test_dashboard_and_ai_status(client, monkeypatch):
    for k in ("AI_API_KEY", "AI_MODEL", "AI_API_URL"): monkeypatch.delenv(k, raising=False)
    signup(client, "ivy")
    client.post("/api/reviews", json=dict(language="python", code="def f(x=[]): pass\n"), headers=H)
    d = client.get("/api/dashboard").get_json()
    assert d["total"] == 1 and d["issues"] >= 1
    s = client.get("/api/ai/status").get_json()
    assert s["configured"] is False and s["missing"] == ["AI_API_KEY", "AI_MODEL", "AI_API_URL"]

def test_ai_client_errors(monkeypatch):
    from services import ai_client
    for k, v in dict(AI_API_KEY="KEY123", AI_MODEL="m", AI_API_URL="http://x").items(): monkeypatch.setenv(k, v)
    class R:
        status_code = 401
        def json(self): return {"error": {"message": "bad key KEY123"}}
    monkeypatch.setattr(ai_client.requests, "post", lambda *a, **kw: R())
    with pytest.raises(ai_client.AIError) as e: ai_client.chat("hi")
    assert "401" in str(e.value) and "bad key ***" in str(e.value)

def _an(c, lang, code): return c.post("/api/analyze", json=dict(language=lang, code=code), headers=H).get_json()["findings"]

def test_no_false_positives_in_strings_and_comments(client):
    signup(client, "joe")
    assert not any("Loose" in f["title"] for f in _an(client, "javascript", 'const s = "a == b";\nconsole.log(s);\n'))
    assert _an(client, "css", "/* a { */\na { color: red; }\n") == []
    assert any(f["title"] == "Hardcoded credential" for f in _an(client, "python", 'db_password = "hunter22"\n'))
    assert any(f["title"] == "Unreachable code" for f in _an(client, "python", "def f():\n    return 1\n    print(2)\n"))

def test_suggestion_and_run(client, monkeypatch):
    for k in ("AI_API_KEY", "AI_MODEL", "AI_API_URL"): monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_CODE_EXECUTION", "true")
    signup(client, "kim")
    code = 'def f(x=[]):\n    try:\n        return x\n    except:\n        pass\n'
    rid = client.post("/api/reviews", json=dict(language="python", code=code), headers=H).get_json()["review"]["id"]
    s = client.get(f"/api/reviews/{rid}/suggestion").get_json()
    assert "except Exception:" in s["code"] and "x=None" in s["code"] and s["score_after"] >= s["score_before"]
    r = client.post("/api/run", json=dict(language="python", code="print(6*7)"), headers=H).get_json()
    assert r["kind"] == "ran" and r["stdout"].strip() == "42"
    monkeypatch.setenv("ENABLE_CODE_EXECUTION", "false")
    assert client.post("/api/run", json=dict(language="python", code="print(1)"), headers=H).get_json()["kind"] == "disabled"

SHOT = "body {\n  background-color: #ffffff\n  color: #333333;\n  font-family: Arial, sans-serif;\n}\n\n.container {\n  width: 100%;\n  padding: 20px;\n  margin: 0 auto\n}\n"
CLEAN = ':root { --brand: #7c5cff; }\n* { box-sizing: border-box; }\n@import url("a.css");\nbody { margin: 0; background: url(data:image/png;base64,AAAA) no-repeat; font: 12px/1.5 "Helvetica Neue", Arial; }\n.a:hover > .b { transition: opacity .3s ease, transform .3s; width: calc(100% - 20px); }\n@media (min-width: 600px) { .a { display: grid; grid-template-columns: repeat(2, 1fr); } }\n@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }\n'

def test_css_parser():
    from analyzers import analyze_code
    from fixer import auto_fix
    got = {(f["line_number"], f["title"]) for f in analyze_code("css", SHOT)}
    assert got == {(2, "Missing semicolon"), (10, "Missing trailing semicolon"), (8, "Width 100% plus padding/border overflows")}
    fixed, changes = auto_fix("css", SHOT)
    assert analyze_code("css", fixed) == [] and "box-sizing: border-box;" in fixed and changes
    assert analyze_code("css", CLEAN) == []
    t = {f["title"] for f in analyze_code("css", "a { colr: red; margin: 10; color: #12; }\nb { color: red;\n")}
    assert {"Unknown property", "Missing unit", "Invalid hex color", "Unclosed block"} <= t

def test_pdf_report(client):
    signup(client, "pat")
    rid = client.post("/api/reviews", json=dict(language="python", code="def f(x=[]): pass\n"), headers=H).get_json()["review"]["id"]
    r = client.get(f"/api/reviews/{rid}/report?format=pdf")
    assert r.status_code == 200 and r.mimetype == "application/pdf" and r.data.startswith(b"%PDF")

def test_settings_history_account(client):
    signup(client, "sam")
    client.post("/api/reviews", json=dict(language="python", code="x = 1\n"), headers=H)
    assert client.put("/api/settings", json=dict(username="sam_2", default_language="go"), headers=H).status_code == 200
    s = client.get("/api/settings").get_json()
    assert s["user"]["username"] == "sam_2" and s["user"]["default_language"] == "go" and s["total_reviews"] == 1
    assert client.put("/api/settings/password", json=dict(current_password="bad", new_password="NewPassw0rd1"), headers=H).status_code == 401
    assert client.put("/api/settings/password", json=dict(current_password=PW, new_password="NewPassw0rd1"), headers=H).status_code == 200
    assert client.delete("/api/reviews", headers=H).status_code == 200 and client.get("/api/reviews").get_json()["reviews"] == []
    assert client.delete("/api/account", json=dict(confirm="nope"), headers=H).status_code == 422
    assert client.delete("/api/account", json=dict(confirm="DELETE", password="NewPassw0rd1"), headers=H).status_code == 200
    assert client.get("/api/auth/me").status_code == 401

def test_old_database_is_migrated(tmp_path):
    import sqlite3
    from werkzeug.security import generate_password_hash
    p = tmp_path / "old.db"; c = sqlite3.connect(p)
    c.execute("CREATE TABLE user (id INTEGER PRIMARY KEY, username VARCHAR(40) NOT NULL, email VARCHAR(120) NOT NULL, password_hash VARCHAR(256) NOT NULL, created_at DATETIME)")
    c.execute("INSERT INTO user VALUES (1, 'old', 'old@x.com', ?, '2026-01-01 00:00:00')", (generate_password_hash(PW),)); c.commit(); c.close()
    cl = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{p}"}).test_client()
    r = cl.post("/api/auth/login", json=dict(identifier="old", password=PW), headers=H)
    assert r.status_code == 200 and r.get_json()["user"]["has_password"] is True


def test_html_ids_are_unique():
    import collections, os, re
    html = open(os.path.join(os.path.dirname(__file__), "..", "templates", "index.html"), encoding="utf-8").read()
    ids = re.findall(r'\sid="([^"]+)"', html)
    assert [k for k, n in collections.Counter(ids).items() if n > 1] == []   # a duplicate id once made the editor read the wrong box

def test_forgot_password_is_gone(client):
    signup(client, "zed")
    assert client.post("/api/auth/forgot", json=dict(email="zed@x.com"), headers=H).status_code in (404, 405)


def test_vercel_entrypoint_exports_app():
    import ast, os
    tree = ast.parse(open(os.path.join(os.path.dirname(__file__), "..", "app.py"), encoding="utf-8").read())
    assert any(isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "app" for t in n.targets) for n in tree.body)   # the exact Vercel error

def test_requirements_not_empty():
    import os
    assert "tree-sitter" in open(os.path.join(os.path.dirname(__file__), "..", "requirements.txt")).read()

def test_db_url_handling(monkeypatch):
    from app import db_url
    for k in ("DATABASE_URL", "POSTGRES_URL", "VERCEL"): monkeypatch.delenv(k, raising=False)
    assert db_url() == "sqlite:///codescan.db"
    monkeypatch.setenv("VERCEL", "1"); assert db_url() == "sqlite:////tmp/codescan.db"
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@h.example/db?sslmode=require&supa=base-pooler.x&pgbouncer=true")
    assert db_url() == "postgresql+psycopg2://u:p@h.example/db?sslmode=require"
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h.example/db"); assert db_url() == "postgresql+psycopg2://u:p@h.example/db"

def test_production_needs_a_real_secret_key(monkeypatch):
    monkeypatch.setenv("VERCEL", "1"); monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:"); monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError): create_app()
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    a = create_app(); assert a.config["SESSION_COOKIE_SECURE"] is True
    assert "max-age" in a.test_client().get("/api/health").headers["Strict-Transport-Security"]

def test_static_files_and_no_code_execution_on_vercel(client, monkeypatch):
    assert client.get("/static/css/style.css").status_code == 200 and client.get("/static/js/app.js").status_code == 200
    from services.runner import run_code
    monkeypatch.setenv("VERCEL", "1"); monkeypatch.setenv("ENABLE_CODE_EXECUTION", "true")
    assert run_code("python", "print(1)")["kind"] == "disabled"

def test_long_email_rejected(client):
    long = "a" * 130 + "@x.com"
    assert client.post("/api/auth/register", json=dict(username="longy", email=long, password=PW, confirm_password=PW), headers=H).status_code == 422


def test_render_environment(monkeypatch):
    from app import db_url
    from services.runner import run_code
    for k in ("DATABASE_URL", "POSTGRES_URL", "VERCEL", "SECRET_KEY"): monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("RENDER", "true")
    assert db_url() == "sqlite:////tmp/codescan.db"
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@dpg-x.oregon-postgres.render.com/db")
    assert db_url() == "postgresql+psycopg2://u:p@dpg-x.oregon-postgres.render.com/db"
    with pytest.raises(RuntimeError): create_app()   # needs SECRET_KEY on Render
    monkeypatch.setenv("SECRET_KEY", "y" * 32); monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:"); monkeypatch.setenv("ENABLE_CODE_EXECUTION", "true")
    assert create_app().config["SESSION_COOKIE_SECURE"] is True and run_code("python", "print(1)")["kind"] == "disabled"


def test_all_errors_are_reported_at_once(client):
    signup(client, "mia")
    code = 'import os\npassword = "hunter22"\n\ndef add(a, b)\n    return a + b\n\ndef sub(a, b=[]):\n    return a - \n\nprint(add(1, 2)\nx = = 3\n'
    f = client.post("/api/analyze", json=dict(language="python", code=code), headers=H).get_json()["findings"]
    assert sorted(x["line_number"] for x in f if x["title"] == "Syntax error") == [4, 8, 10, 11]
    assert {"Hardcoded credential", "Mutable default argument"} <= {x["title"] for x in f}

def test_many_errors_in_a_big_file_is_fast():
    import time
    from analyzers import analyze_code
    code = "\n".join(f"def f{i}(a)\n    return a" if i % 50 == 0 else f"def f{i}(a):\n    return a" for i in range(1500))
    t = time.time(); r = analyze_code("python", code); took = time.time() - t
    assert sum(1 for x in r if x["title"] == "Syntax error") == 30 and took < 15, took


def test_runtime_errors_all_reported_together(client):
    signup(client, "ned")
    code = 'name = input("Enter your name: ")\nage = int(input("Enter your age: "))\nprint("Welcome", name)\ntotal = age + "5"\nprint("Thank you", nam)\n'
    f = client.post("/api/analyze", json=dict(language="python", code=code), headers=H).get_json()["findings"]
    got = {(x["line_number"], x["title"]) for x in f}
    assert {(4, "Type error: unsupported operand types"), (5, "Undefined name")} <= got and len(f) == 3
    nam = next(x for x in f if x["title"] == "Undefined name"); assert "name" in nam["recommendation"] and "name" in nam["suggested_fix"]

def test_type_checker_is_conservative():
    from analyzers import analyze_code
    ok = 'x = 1\nif input():\n    x = "a"\ny = x + 1\n\ndef f():\n    global g\n    g = "s"\n\n\ng = 1\nf()\nprint(g + "z")\nz = [1] * 3\nw = "a" % 5\n'
    assert [f for f in analyze_code("python", ok) if f["category"] == "Bug"] == []   # unknown or merged types never produce a claim

def test_debug_status_and_review_debug_info(client):
    signup(client, "dee")
    s = client.get("/api/debug/status").get_json()
    assert {"python", "typescript", "java", "c", "csharp", "go", "kotlin", "swift", "bash", "css"} <= set(s["languages"]) and s["languages"]["python"]["run"] is True
    assert s["languages"]["css"]["run_tool"] == "browser preview"
    d = client.post("/api/reviews", json=dict(language="python", code="x = 1 +\n"), headers=H).get_json()["debug"]
    assert d["engine"] == "Python ast (exact)" and d["syntax_errors"] == 1 and d["compiler"]["ran"] is False and d["analysis_ms"] >= 0
    client.post("/api/auth/logout", headers=H); assert client.get("/api/debug/status").status_code == 401

PLAIN = 'name = input("Enter your name: ")\nage = input("Enter your age: ")\nprint("Hello" + name)\nage = int(age)\nif age > 18\n    print("You are an adult")\nelse:\n    print("You are a minor")\nprint("Welcome" + nam)\nprint("Your age is " + age)\n'

def test_strip_line_numbers_formats_and_negatives():
    from analyzers import strip_line_numbers
    lines = PLAIN.rstrip("\n").split("\n")
    for fmt in ("{n}. {t}", "{n}) {t}", "{n}: {t}", "{n} | {t}", "{n}\t{t}", "  {n}. {t}"):
        s = "\n".join(fmt.format(n=i, t=t) for i, t in enumerate(lines, 1)) + "\n"
        out, note = strip_line_numbers(s)
        assert out.strip("\n") == PLAIN.strip("\n") and note, fmt            # numbers gone, indentation kept
    for keep in (PLAIN, 'd = {\n  1: "a",\n  2: "b",\n  3: "c",\n}\n', "1. one\n2. two\n", "x = 1\n2. y\nz = 3\nw = 4\n", "1. a\n7. b\n3. c\n9. d\n"):
        assert strip_line_numbers(keep) == (keep, ""), keep                    # real code / too few lines / numbers that do not count up

def test_pasted_line_numbers_are_ignored_end_to_end(client):
    signup(client, "lou")
    numbered = "\n".join(f"{i}. {t}" for i, t in enumerate(PLAIN.rstrip("\n").split("\n"), 1)) + "\n"
    r = client.post("/api/reviews", json=dict(language="python", code=numbered), headers=H).get_json()
    got = {(f["line_number"], f["title"]) for f in r["review"]["findings"]}
    assert got == {(5, "Syntax error"), (9, "Undefined name"), (10, "Type error: unsupported operand types")}, got
    assert r["review"]["summary"].startswith("Line numbers at the start") and r["review"]["source_code"] == PLAIN and r["debug"]["line_numbers_removed"] is True

def test_undefined_names_still_reported_next_to_syntax_errors():
    from analyzers import analyze_code
    titles = lambda code: {(f["line_number"], f["title"]) for f in analyze_code("python", code)}
    assert (1, "Undefined name") in titles("print(y)\nz = = 1\n")            # y is defined nowhere
    assert (2, "Undefined name") not in titles("x = = 3\nprint(x)\n")        # x may be defined on the broken line: no false alarm
