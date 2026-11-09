"""Language toolchains: finds the compilers/interpreters installed on THIS computer, runs programs in every supported
language, and collects real compiler diagnostics for the reviewer. Never used on public hosting (see runner.enabled())."""
import functools, os, re, shutil, subprocess, sys, tempfile, time

EXE = ".exe" if os.name == "nt" else ""
CAP = 20000
SENSITIVE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)|^(AI_|DATABASE_URL|POSTGRES_|SMTP_)", re.I)
NAMES = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript", "java": "Java", "c": "C", "cpp": "C++", "csharp": "C#", "go": "Go",
         "php": "PHP", "ruby": "Ruby", "rust": "Rust", "kotlin": "Kotlin", "swift": "Swift", "bash": "Bash", "sql": "SQL", "html": "HTML", "css": "CSS"}
HINT = {"javascript": "Install Node.js from https://nodejs.org and restart CodeScan.",
        "typescript": "Install Node.js 22.6+ (https://nodejs.org), or run: npm i -g tsx",
        "java": "Install a JDK (not just a JRE), e.g. from https://adoptium.net, and restart CodeScan.",
        "c": "Install gcc or clang (Windows: MSYS2/MinGW-w64 or 'winget install LLVM.LLVM'), then restart.",
        "cpp": "Install g++ or clang++ (Windows: MSYS2/MinGW-w64 or 'winget install LLVM.LLVM'), then restart.",
        "csharp": "Install the .NET SDK from https://dotnet.microsoft.com/download (or Mono), then restart.",
        "go": "Install Go from https://go.dev/dl and restart CodeScan.",
        "php": "Install PHP from https://www.php.net/downloads and restart CodeScan.",
        "ruby": "Install Ruby from https://www.ruby-lang.org/en/downloads and restart CodeScan.",
        "rust": "Install Rust with rustup from https://rustup.rs and restart CodeScan.",
        "kotlin": "Install the Kotlin compiler (https://kotlinlang.org/docs/command-line.html) and a JDK, then restart.",
        "swift": "Install Swift from https://www.swift.org/install and restart CodeScan.",
        "bash": "Install bash (Windows: Git for Windows or WSL), then restart CodeScan.",
        "python": "Python is required to run CodeScan itself."}
_s = lambda x: x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")

def hosted(): return bool(os.getenv("VERCEL") or os.getenv("RENDER"))
def which(*names):
    for n in names:
        p = shutil.which(n)
        if p: return p
    return None

def limits(cpu):
    def f():  # POSIX only: CPU seconds and written file size
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu)); resource.setrlimit(resource.RLIMIT_FSIZE, (200 * 2**20,) * 2)
    return f

def step_env(d):
    env = {k: v for k, v in os.environ.items() if not SENSITIVE.search(k)}   # keep the user's tool setup, drop this app's secrets
    env.update(TMPDIR=d, TEMP=d, TMP=d, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", GOFLAGS="-buildvcs=false", GOTOOLCHAIN="local",
               DOTNET_CLI_HOME=d, DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
    return env

@functools.lru_cache(maxsize=32)
def version(exe):
    flag = ["-version"] if os.path.basename(exe).split(".")[0] in ("java", "javac", "kotlinc") else ["version"] if os.path.basename(exe).startswith("go") else ["--version"]
    try:
        r = subprocess.run([exe] + flag, capture_output=True, text=True, timeout=15, input="")
        return ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[0][:80]
    except Exception: return ""

def major(exe, rx=r"(\d+)"):
    m = re.search(rx, version(exe)); return int(m.group(1)) if m else 0

def java_class(src):
    pub = re.search(r"\bpublic\s+(?:final\s+|abstract\s+)*(?:class|record|enum|interface)\s+(\w+)", src)
    any_ = re.search(r"\b(?:class|record|enum|interface)\s+(\w+)", src)
    return (pub or any_).group(1) if (pub or any_) else "Main"

SQL_RUNNER = r'''import re, sqlite3, sys
con = sqlite3.connect(":memory:")
con.set_authorizer(lambda action, *a: sqlite3.SQLITE_DENY if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH) else sqlite3.SQLITE_OK)
def show(sql):
    cur = con.execute(sql)
    if cur.description:
        cols = [c[0] for c in cur.description]; rows = cur.fetchmany(200)
        print(" | ".join(cols)); print("-+-".join("-" * len(c) for c in cols))
        for r in rows: print(" | ".join("NULL" if v is None else str(v) for v in r))
        print("(%d row(s))\n" % len(rows))
stmts, cur = [], ""
for chunk in re.split(r"(;)", open(sys.argv[1], encoding="utf-8").read()):
    cur += chunk
    if chunk == ";" and sqlite3.complete_statement(cur): stmts.append(cur); cur = ""
if cur.strip(): stmts.append(cur)
for s in stmts:
    if not s.strip().strip(";").strip(): continue
    try: show(s)
    except sqlite3.Error as e: print("Error: %s\n  in: %s" % (e, s.strip()[:200]), file=sys.stderr); sys.exit(1)
'''

def plan(lang, d, src):
    """-> (steps, missing). steps = [(label, argv, timeout)]; missing = (what_is_needed, install_hint) or None."""
    def w(name, text=None):
        with open(os.path.join(d, name), "w", encoding="utf-8", newline="\n") as fh: fh.write(src if text is None else text)
    p = lambda n: os.path.join(d, n)
    exe = lambda n: p(n + EXE)
    miss = lambda what: (None, (what, HINT.get(lang, "")))
    if lang == "python": w("main.py"); return [("run", [sys.executable, "-I", "main.py"], 5)], None
    if lang == "sql": w("main.sql"); w("sql_runner.py", SQL_RUNNER); return [("run", [sys.executable, "-I", "sql_runner.py", "main.sql"], 5)], None
    if lang == "javascript":
        n = which("node")
        if not n: return miss("Node.js")
        w("main.js"); return [("run", [n, "main.js"], 5)], None
    if lang == "typescript":
        w("main.ts"); node = which("node")
        if which("tsx"): return [("run", [which("tsx"), "main.ts"], 10)], None
        if node and major(node, r"v(\d+)") >= 22: return [("run", [node, "--experimental-strip-types", "--no-warnings", "main.ts"], 8)], None
        if which("deno"): return [("run", [which("deno"), "run", "--quiet", "main.ts"], 10)], None
        if which("bun"): return [("run", [which("bun"), "main.ts"], 8)], None
        if which("ts-node"): return [("run", [which("ts-node"), "--transpile-only", "main.ts"], 10)], None
        return miss("Node.js 22.6+ (or tsx / deno / bun)")
    if lang == "java":
        jc, j = which("javac"), which("java")
        if not (jc and j): return miss("a JDK (javac + java)")
        cls = java_class(src); w(cls + ".java"); os.makedirs(p("out"), exist_ok=True)
        return [("compile", [jc, "-Xmaxerrs", "100", "-d", "out", cls + ".java"], 90), ("run", [j, "-cp", "out", cls], 8)], None
    if lang in ("c", "cpp"):
        cc = which("gcc", "cc", "clang") if lang == "c" else which("g++", "c++", "clang++")
        if not cc: return miss("a C compiler (gcc / clang)" if lang == "c" else "a C++ compiler (g++ / clang++)")
        f = "main." + lang; w(f)
        return [("compile", [cc, f, "-o", exe("main")] + (["-lm"] if lang == "c" else ["-std=c++17"]), 90), ("run", [exe("main")], 5)], None
    if lang == "csharp":
        dn = which("dotnet")
        if dn:
            w("Program.cs"); w("app.csproj", f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net{major(dn) or 8}.0</TargetFramework><ImplicitUsings>disable</ImplicitUsings><Nullable>disable</Nullable><InvariantGlobalization>true</InvariantGlobalization></PropertyGroup></Project>')
            return [("compile", [dn, "build", "-c", "Release", "-o", "out", "--nologo", "-v", "q"], 180), ("run", [dn, p("out/app.dll")], 8)], None
        if os.name == "nt" and which("csc"): w("main.cs"); return [("compile", [which("csc"), "/nologo", "/out:main.exe", "main.cs"], 90), ("run", [p("main.exe")], 5)], None
        if which("mcs") and which("mono"): w("main.cs"); return [("compile", [which("mcs"), "-out:main.exe", "main.cs"], 90), ("run", [which("mono"), "main.exe"], 5)], None
        return miss("the .NET SDK (or Mono)")
    if lang == "go":
        g = which("go")
        if not g: return miss("Go")
        w("main.go"); return [("compile", [g, "build", "-o", exe("main"), "main.go"], 120), ("run", [exe("main")], 5)], None
    if lang == "php":
        n = which("php")
        if not n: return miss("PHP")
        w("main.php"); return [("run", [n, "main.php"], 5)], None
    if lang == "ruby":
        n = which("ruby")
        if not n: return miss("Ruby")
        w("main.rb"); return [("run", [n, "main.rb"], 5)], None
    if lang == "rust":
        n = which("rustc")
        if not n: return miss("Rust (rustc)")
        w("main.rs"); return [("compile", [n, "--edition", "2021", "main.rs", "-o", exe("main")], 120), ("run", [exe("main")], 5)], None
    if lang == "kotlin":
        kc, j = which("kotlinc"), which("java")
        if not (kc and j): return miss("kotlinc and a JDK")
        w("main.kt"); return [("compile", [kc, "main.kt", "-include-runtime", "-d", "main.jar"], 240), ("run", [j, "-jar", "main.jar"], 8)], None
    if lang == "swift":
        n = which("swiftc")
        if not n: return miss("Swift (swiftc)")
        w("main.swift"); return [("compile", [n, "main.swift", "-o", exe("main")], 180), ("run", [exe("main")], 5)], None
    if lang == "bash":
        n = which("bash")
        if not n: return miss("bash")
        w("main.sh"); return [("run", [n, "main.sh"], 5)], None
    return None, (NAMES.get(lang, lang), "")

def run_steps(steps, d, run_timeout=None):
    env, log, so, se, code, timed, failed = step_env(d), [], "", "", 0, False, False
    for label, argv, timeout in steps:
        timeout = run_timeout if (label == "run" and run_timeout) else timeout
        t = time.time(); timed = False
        try:
            r = subprocess.run(argv, cwd=d, env=env, input=b"", capture_output=True, timeout=timeout, preexec_fn=limits(int(timeout) + 3) if os.name == "posix" else None)
            so, se, code = _s(r.stdout), _s(r.stderr), r.returncode
        except subprocess.TimeoutExpired as e: so, se, code, timed = _s(e.stdout), _s(e.stderr), -1, True
        except OSError as e: so, se, code = "", f"could not start {os.path.basename(argv[0])}: {e}", -1
        ms = int((time.time() - t) * 1000)
        log.append({"step": label, "cmd": " ".join(os.path.basename(argv[0]) if i == 0 else a.replace(d, ".") for i, a in enumerate(argv)), "exit": code, "ms": ms, "timed_out": timed})
        if label == "compile" and (code != 0 or timed):
            failed = True; so, se = "", (so + se) if not timed else "The compiler took too long (timeout)."
            break
    clean = lambda s: s.replace(d, ".")[:CAP]
    return {"kind": "ran", "phase": "compile" if failed else "run", "stdout": clean(so), "stderr": clean(se), "exit_code": code, "duration_ms": log[-1]["ms"], "timed_out": timed, "steps": log}

# ---------------- compiler diagnostics for the reviewer (never runs the program)
GCC = r"^main\.\w+:(?P<line>\d+):(?:\d+:)? (?P<sev>fatal error|error|warning): (?P<msg>.*)$"
def check_plan(lang, d, src):
    """-> (argv, regex) or None when no checker is installed."""
    def w(name):
        with open(os.path.join(d, name), "w", encoding="utf-8", newline="\n") as fh: fh.write(src)
    if lang in ("c", "cpp"):
        cc = which("gcc", "cc", "clang") if lang == "c" else which("g++", "c++", "clang++")
        if cc: f = "main." + lang; w(f); return [cc, "-fsyntax-only", "-Wall", f] + (["-std=c++17"] if lang == "cpp" else []), GCC
    elif lang == "java" and which("javac"):
        cls = java_class(src); w(cls + ".java"); os.makedirs(os.path.join(d, "out"), exist_ok=True)
        return [which("javac"), "-Xmaxerrs", "100", "-d", "out", cls + ".java"], r"^\S*\.java:(?P<line>\d+): (?P<sev>error|warning): (?P<msg>.*)$"
    elif lang == "go" and which("go"):
        w("main.go"); return [which("go"), "build", "-gcflags=-e", "-o", os.path.join(d, "out" + EXE), "main.go"], r"^(?:\./)?main\.go:(?P<line>\d+):\d+: (?P<msg>.*)$"
    elif lang == "rust" and which("rustc"):
        w("main.rs"); return [which("rustc"), "--edition", "2021", "--error-format=short", "--emit=metadata", "-o", os.path.join(d, "out.rmeta"), "main.rs"], r"^main\.rs:(?P<line>\d+):\d+: (?P<sev>error|warning)(?:\[\w+\])?: (?P<msg>.*)$"
    elif lang == "typescript" and which("tsc"):
        w("main.ts"); return [which("tsc"), "--noEmit", "--pretty", "false", "--target", "es2020", "--skipLibCheck", "main.ts"], r"^main\.ts\((?P<line>\d+),\d+\): (?P<sev>error|warning) TS\d+: (?P<msg>.*)$"
    elif lang == "php" and which("php"):
        w("main.php"); return [which("php"), "-l", "main.php"], r"(?:PHP )?(?:Parse|Fatal) error:\s*(?P<msg>.*?) in .*?main\.php on line (?P<line>\d+)"
    elif lang == "ruby" and which("ruby"):
        w("main.rb"); return [which("ruby"), "-wc", "main.rb"], (r"^main\.rb:(?P<line>\d+): (?:(?P<sev>warning): )?(?P<msg>.*)$", r"^[> ]\s+(?P<line>\d+) \|[^\n]*\n\s+\|\s*\^[~^]*\s*(?P<msg>[^\n]+)")   # old format, and Ruby 3.4+/4 (prism) format
    elif lang == "bash" and which("bash"):
        w("main.sh"); return [which("bash"), "-n", "main.sh"], r"^main\.sh: line (?P<line>\d+): (?P<msg>.*)$"
    elif lang == "swift" and which("swiftc"):
        w("main.swift"); return [which("swiftc"), "-typecheck", "main.swift"], r"^main\.swift:(?P<line>\d+):\d+: (?P<sev>error|warning): (?P<msg>.*)$"
    return None

def checks_enabled(): return not hosted() and (os.getenv("COMPILER_CHECKS") or "true").lower() != "false"
DEPS = re.compile(r"No such file or directory|package .{0,80}does not exist|cannot find package|no required module|can't find crate|use of undeclared crate|unresolved import|TS2307|TS2688|cannot find -l", re.I)

def diagnostics(lang, src):
    """-> (diagnostics, info). Real compiler errors/warnings if the language's compiler is installed; else ([], why-skipped)."""
    info = {"ran": False}
    if not checks_enabled(): info["skipped"] = "disabled (hosted deployment or COMPILER_CHECKS=false)"; return [], info
    with tempfile.TemporaryDirectory() as d:
        cp = check_plan(lang, d, src)
        if cp is None: info["skipped"] = "no compiler/checker installed for this language"; return [], info
        argv, rx = cp; t = time.time()
        try: r = subprocess.run(argv, cwd=d, env=step_env(d), input=b"", capture_output=True, timeout=30, preexec_fn=limits(33) if os.name == "posix" else None)
        except (subprocess.TimeoutExpired, OSError) as e: info["skipped"] = f"checker failed: {type(e).__name__}"; return [], info
        text = _s(r.stdout) + "\n" + _s(r.stderr)
    info.update(ran=True, tool=os.path.basename(argv[0]), cmd=" ".join(os.path.basename(argv[0]) if i == 0 else a.replace(d, ".") for i, a in enumerate(argv)), exit=r.returncode, ms=int((time.time() - t) * 1000))
    if DEPS.search(text): info["skipped"] = "the code needs libraries that are not installed here; compiler output ignored"; return [], info
    out, seen = [], set()
    for m in (m for r_ in (rx if isinstance(rx, tuple) else (rx,)) for m in re.finditer(r_, text, re.M)):
        g = m.groupdict(); sev = "warning" if (g.get("sev") or "").lower() == "warning" else "error"
        key = (int(g["line"]), g["msg"].strip()[:150])
        if key not in seen and len(out) < 50: seen.add(key); out.append({"line": key[0], "sev": sev, "msg": key[1]})
    info["errors"], info["warnings"] = sum(1 for x in out if x["sev"] == "error"), sum(1 for x in out if x["sev"] == "warning")
    return out, info

_status = {"at": 0, "data": None}
def status():
    """What this computer can do per language (cached 60 s): review engine, compiler check, run toolchain, installation hint."""
    if _status["data"] and time.time() - _status["at"] < 60: return _status["data"]
    from analyzers import LANG_KEY
    from parsing import engine_for
    out = {}
    for lang in LANG_KEY:
        with tempfile.TemporaryDirectory() as d:
            if lang in ("html", "css"): steps, miss = [("preview", ["preview"], 0)], None
            else: steps, miss = plan(lang, d, "")
            cp = None if lang in ("html", "css") else check_plan(lang, tempfile.mkdtemp(dir=d), "")
        tool = steps[0][1][0] if steps else None
        out[lang] = {"name": NAMES.get(lang, lang), "engine": engine_for(lang), "check": os.path.basename(cp[0][0]) if cp else None,
                     "run": miss is None, "run_tool": "browser preview" if lang in ("html", "css") else os.path.basename(tool) if tool else None,
                     "version": version(tool) if tool and lang not in ("html", "css") and os.path.exists(tool) else "", "hint": "" if miss is None else f"needs {miss[0]}. {miss[1]}"}
    _status.update(at=time.time(), data=out); return out
