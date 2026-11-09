"""Static analysis engine: per-language analyzers + scoring.
Scoring: each finding costs points = SEVERITY_WEIGHT * STATUS_FACTOR.
Overall = 100 - total cost (min 0). Sub-scores use only their categories."""
import ast, builtins, difflib, os, re, shutil, subprocess, tempfile
from html.parser import HTMLParser

SEV = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}
STATUS = {"Confirmed": 1.0, "Potential": 0.6, "Suggestion": 0.3}
ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def F(line, code, cat, sev, title, why, impact, rec, fix="", conf=0.8, status="Potential"):
    return dict(category=cat, severity=sev, title=title, line_number=line, code=(code or "").strip()[:300],
                explanation=why, impact=impact, recommendation=rec, suggested_fix=fix,
                confidence=conf, status=status, source="static")

SECRET = r"""(?i)\w*(password|passwd|secret|api[_-]?key|token)\w*["']?\s*[:=]\s*["'][^"'\s]{4,}["']"""
SQLCAT = r"""(?i)["']((select\b[^\n]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b))[^\n]*?["']\s*(\+|%\s*[\w(]|\.format\()|\bf["']((select\b[^\n]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b))[^"'\n]*\{|`((select\b[^\n]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b))[^`\n]*\$\{|\bexecute\w*\(\s*f["'](select|insert|update|delete)\b"""
# (languages, regex, category, severity, title, why, impact, recommendation, fix, status)
RULES = [
 ("all", SECRET, "Security", "HIGH", "Hardcoded credential", "A secret appears to be embedded in source.", "Anyone with repo access can read it.", "Load secrets from environment variables.", "value = os.environ['SECRET_NAME']", "Potential"),
 ("all", SQLCAT, "Security", "HIGH", "Possible SQL injection", "SQL is built by string concatenation/formatting.", "Attackers may alter the query.", "Use parameterized queries.", "cursor.execute('SELECT * FROM users WHERE name = %s', (username,))", "Potential"),
 ("js", r"\beval\s*\(", "Security", "HIGH", "Use of eval()", "eval executes arbitrary strings as code.", "Code injection.", "Avoid eval; parse data with JSON.parse.", "", "Confirmed"),
 ("js", r"\.innerHTML\s*=|document\.write\s*\(", "Security", "MEDIUM", "Unsafe DOM write (XSS risk)", "Raw HTML is inserted into the DOM.", "XSS if the value is user-controlled.", "Use textContent or sanitize.", "el.textContent = value;", "Potential"),
 ("js", r"^\s*var\s+", "Quality", "LOW", "var used instead of let/const", "var is function-scoped and hoisted.", "Scope bugs.", "Use const or let.", "", "Suggestion"),
 ("js", r"[^=!]==[^=]", "Bug", "LOW", "Loose equality (==)", "== performs type coercion.", "Unexpected comparisons.", "Use ===.", "", "Suggestion"),
 ("js", r"catch\s*\([^)]*\)\s*\{\s*\}", "Bug", "MEDIUM", "Empty catch block", "Errors are silently swallowed.", "Failures go unnoticed.", "Handle or log the error.", "", "Confirmed"),
 ("js", r"setInterval\(\s*[\"']|setTimeout\(\s*[\"']", "Security", "MEDIUM", "String passed to timer", "Behaves like eval.", "Code injection.", "Pass a function.", "", "Confirmed"),
 ("py", r"\b(pickle|marshal)\.loads?\(|yaml\.load\((?!.*Loader)", "Security", "HIGH", "Unsafe deserialization", "Untrusted data can run code when deserialized.", "Remote code execution.", "Use json or yaml.safe_load.", "yaml.safe_load(data)", "Potential"),
 ("py", r"\b(md5|sha1)\b\s*\(|hashlib\.(md5|sha1)", "Security", "MEDIUM", "Weak hash algorithm", "MD5/SHA1 are broken for security use.", "Forgeable hashes.", "Use SHA-256+ or a password hasher.", "", "Potential"),
 ("py", r"requests\.\w+\([^)]*verify\s*=\s*False", "Security", "MEDIUM", "TLS verification disabled", "Certificates are not checked.", "Man-in-the-middle.", "Remove verify=False.", "", "Confirmed"),
 ("java", r"Runtime\.getRuntime\(\)\.exec|new ProcessBuilder", "Security", "HIGH", "OS command execution", "Process spawning with possibly tainted input.", "Command injection.", "Validate input / avoid shell.", "", "Potential"),
 ("java", r"\.printStackTrace\(\)", "Quality", "LOW", "printStackTrace used", "Stack traces go to stderr unlogged.", "Leaks details, poor observability.", "Use a logger.", "", "Suggestion"),
 ("java", r"catch\s*\([^)]*\)\s*\{\s*\}", "Bug", "MEDIUM", "Empty catch block", "Exception swallowed.", "Hidden failures.", "Handle or log.", "", "Confirmed"),
 ("~java", r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", "Security", "MEDIUM", "Weak hash algorithm", "MD5/SHA1 are weak.", "Forgeable hashes.", "Use SHA-256+.", "", "Confirmed"),
 ("php", r"\beval\s*\(", "Security", "HIGH", "Use of eval()", "eval executes arbitrary strings as code.", "Code injection.", "Avoid eval.", "", "Confirmed"),
 ("php", r"\b(mysql_query|mysqli_query)\s*\(.*\$_(GET|POST|REQUEST)", "Security", "HIGH", "Possible SQL injection", "Request input flows into a query.", "Query manipulation.", "Use prepared statements (PDO).", "", "Potential"),
 ("php", r"\b(echo|print)\b.*\$_(GET|POST|REQUEST)", "Security", "MEDIUM", "Unescaped output (XSS risk)", "Request data is printed raw.", "XSS.", "Wrap in htmlspecialchars().", "echo htmlspecialchars($_GET['q'], ENT_QUOTES);", "Potential"),
 ("php", r"\b(system|exec|shell_exec|passthru)\s*\(", "Security", "HIGH", "OS command execution", "Process spawning with possibly tainted input.", "Command injection.", "Avoid or use escapeshellarg().", "", "Potential"),
 ("c,cpp", r"\bgets\s*\(", "Security", "CRITICAL", "Use of gets()", "gets has no bounds checking.", "Buffer overflow.", "Use fgets.", "fgets(buf, sizeof buf, stdin);", "Confirmed"),
 ("c,cpp", r"\b(strcpy|strcat|sprintf)\s*\(", "Security", "HIGH", "Unbounded string function", "No length limit on the copy.", "Buffer overflow.", "Use strncpy/snprintf.", "", "Potential"),
 ("c,cpp", r"\bsystem\s*\(", "Security", "MEDIUM", "system() call", "Runs a shell command.", "Command injection.", "Avoid the shell.", "", "Potential"),
 ("go", r"InsecureSkipVerify\s*:\s*true", "Security", "MEDIUM", "TLS verification disabled", "Certificates are not checked.", "Man-in-the-middle.", "Remove InsecureSkipVerify.", "", "Confirmed"),
 ("go", r"\b_\s*(:=|=)\s*[\w.]+\(", "Bug", "LOW", "Error value ignored", "Return value discarded with _.", "Failures go unnoticed.", "Check the error.", "", "Suggestion"),
 ("go", r"exec\.Command\(", "Security", "MEDIUM", "OS command execution", "Process spawning.", "Command injection if input is tainted.", "Validate arguments.", "", "Potential"),
 ("ruby", r"\beval\s*\(|\binstance_eval\b", "Security", "HIGH", "Use of eval", "Executes strings as code.", "Code injection.", "Avoid eval.", "", "Confirmed"),
 ("ruby", r"Marshal\.load|YAML\.load\(", "Security", "HIGH", "Unsafe deserialization", "Can instantiate arbitrary objects.", "Remote code execution.", "Use JSON or YAML.safe_load.", "", "Potential"),
 ("ruby", r"%x\(|\bsystem\s*\(|`[^`]*#\{", "Security", "MEDIUM", "Shell command execution", "Interpolated shell command.", "Command injection.", "Pass arguments as an array.", "", "Potential"),
 ("rust", r"\.unwrap\(\)", "Bug", "LOW", "unwrap() may panic", "Panics on Err/None.", "Crash at runtime.", "Handle the error or use ?.", "", "Suggestion"),
 ("rust", r"\bunsafe\s*\{", "Security", "MEDIUM", "unsafe block", "Bypasses compiler guarantees.", "Memory-safety bugs.", "Justify and minimise unsafe.", "", "Potential"),
 ("csharp", r"catch\s*(\([^)]*\))?\s*\{\s*\}", "Bug", "MEDIUM", "Empty catch block", "Exception swallowed.", "Hidden failures.", "Handle or log.", "", "Confirmed"),
 ("csharp", r"BinaryFormatter", "Security", "HIGH", "Insecure deserialization", "BinaryFormatter is unsafe.", "Remote code execution.", "Use System.Text.Json.", "", "Confirmed"),
 ("csharp", r"Process\.Start\(", "Security", "MEDIUM", "OS command execution", "Process spawning.", "Command injection if tainted.", "Validate input.", "", "Potential"),
 ("csharp", r"\b(MD5|SHA1)\.Create\(|MD5CryptoServiceProvider", "Security", "MEDIUM", "Weak hash algorithm", "MD5/SHA1 are weak.", "Forgeable hashes.", "Use SHA-256+.", "", "Confirmed"),
 ("kotlin", r"catch\s*\([^)]*\)\s*\{\s*\}", "Bug", "MEDIUM", "Empty catch block", "Exception swallowed.", "Hidden failures.", "Handle or log.", "", "Confirmed"),
 ("kotlin", r"!!", "Bug", "LOW", "Non-null assertion (!!)", "Throws NPE on null.", "Crash at runtime.", "Use safe calls or checks.", "", "Suggestion"),
 ("swift", r"\btry!|\bas!", "Bug", "LOW", "Forced try/cast", "Crashes on failure.", "Runtime crash.", "Use do/catch or as?.", "", "Suggestion"),
 ("sql", r"(?i)\bselect\s+\*", "Performance", "LOW", "SELECT * used", "Fetches every column.", "Wasted I/O, fragile code.", "List needed columns.", "", "Suggestion"),
 ("sql", r"(?i)^\s*(delete\s+from\s+\w+|update\s+\w+\s+set\s+[^;]*?)\s*;?\s*$", "Bug", "HIGH", "DELETE/UPDATE without WHERE", "Statement has no WHERE clause.", "Affects every row.", "Add a WHERE clause.", "", "Potential"),
 ("sql", r"(?i)\bdrop\s+(table|database)\b|\bgrant\s+all\b", "Security", "MEDIUM", "Destructive/over-broad statement", "DROP or GRANT ALL found.", "Data loss or excess privileges.", "Review necessity.", "", "Potential"),
 ("bash", r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh", "Security", "HIGH", "Piping download into shell", "Runs unverified remote code.", "Remote code execution.", "Download, verify, then run.", "", "Confirmed"),
 ("bash", r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|\"?\$)", "Bug", "HIGH", "Dangerous rm -rf target", "Unset variable could expand to /.", "Data loss.", "Quote and validate the path.", "", "Potential"),
 ("bash", r"\beval\b", "Security", "MEDIUM", "Use of eval", "Executes strings as code.", "Command injection.", "Avoid eval.", "", "Potential"),
 ("bash", r"\bchmod\s+(-R\s+)?777", "Security", "MEDIUM", "World-writable permissions", "chmod 777 grants everyone write.", "Tampering.", "Use least privilege.", "", "Confirmed"),
 ("java", r"(==|!=)\s*\"|\"\s*(==|!=)", "Bug", "MEDIUM", "String compared with ==", "== compares references, not text.", "Wrong results.", "Use .equals().", "\"text\".equals(value)", "Potential"),
]
LANG_KEY = {"python": "py", "javascript": "js", "typescript": "js", "java": "java", "css": "css", "html": "html",
            "c": "c", "cpp": "cpp", "csharp": "csharp", "go": "go", "php": "php", "ruby": "ruby", "rust": "rust",
            "kotlin": "kotlin", "swift": "swift", "sql": "sql", "bash": "bash"}
BRACE = {"javascript", "typescript", "java", "c", "cpp", "csharp", "go", "php", "rust", "kotlin", "swift"}

COMMENT = {"py": r"(?<![\w$\{])#[^\n]*", "ruby": r"(?<![\w$\{])#[^\n]*", "bash": r"(?<![\w$\{])#[^\n]*",
           "sql": r"--[^\n]*|/\*[\s\S]*?\*/", "html": r"<!--[\s\S]*?-->", "css": r"/\*[\s\S]*?\*/",
           "php": r"//[^\n]*|(?<![\w$\{])#[^\n]*|/\*[\s\S]*?\*/"}
STRING = r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'"

def _regex_mask(src, lang, blank_strings=True):
    """Blank comments (and string contents) so rules never fire on text that is not code.
    Length and line breaks are preserved, so positions map 1:1 onto the original source."""
    k = LANG_KEY[lang]
    parts = ["(?P<c>%s)" % COMMENT.get(k, r"//[^\n]*|/\*[\s\S]*?\*/")]
    if k != "html":
        st = STRING
        if k == "py": st = r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|' + st
        if k in ("js", "go"): st += r"|`(?:\\.|[^`\\])*`"
        parts.append("(?P<s>%s)" % st)
    blank = lambda t: re.sub(r"[^\n]", " ", t)
    def sub(m):
        t = m.group(0)
        if m.lastgroup == "c": return blank(t)
        return t[0] + blank(t[1:-1]) + t[-1] if blank_strings else t
    return re.compile("|".join(parts)).sub(sub, src)

def mask(src, lang, blank_strings=True):
    """Blank comments/strings. Uses the real parser when available, else the regex fallback."""
    from parsing import ts_mask
    m = ts_mask(lang, src, blank_strings)
    return m if m is not None else _regex_mask(src, lang, blank_strings)

def run_rules(lang, src):
    k, lines = LANG_KEY[lang], src.splitlines()
    code, text = mask(src, lang).splitlines(), mask(src, lang, False).splitlines()
    out = []
    for langs, rx, cat, sev, title, why, imp, rec, fix, status in RULES:
        raw = langs == "all" or langs.startswith("~")   # string-aware rules see string contents
        langs = langs.lstrip("~")
        if langs != "all" and k not in langs.split(","): continue
        r = re.compile(rx)
        for i, ln in enumerate(text if raw else code, 1):
            if r.search(ln): out.append(F(i, lines[i - 1] if i <= len(lines) else ln, cat, sev, title, why, imp, rec, fix, 0.75, status))
    return out

class PythonAnalyzer:
    def analyze(self, src, lines):
        from parsing import all_syntax_errors
        errs, neutral = all_syntax_errors("python", src)
        syn = [F(ln, lines[ln - 1] if 0 < ln <= len(lines) else "", "Bug", "CRITICAL", "Syntax error", msg, "The code will not run.", "Fix the syntax on this line.", conf=1.0, status="Confirmed") for ln, msg in errs]
        try: tree = ast.parse(neutral)
        except (SyntaxError, ValueError): return syn + run_rules("python", src)
        bad = {ln for ln, _ in errs}
        return syn + [f for f in self.checks(tree, lines, bad) if f["line_number"] not in bad] + run_rules("python", src)

    def checks(self, tree, lines, bad):
        out = []
        line = lambda n: lines[n - 1] if 0 < n <= len(lines) else ""
        for n in ast.walk(tree):
            ln = getattr(n, "lineno", 1)
            if isinstance(n, ast.Call):
                name = ast.unparse(n.func)
                if name in ("eval", "exec"):
                    out.append(F(ln, line(ln), "Security", "HIGH", f"Dangerous {name}()", f"{name} runs arbitrary code.", "Code injection.", "Use ast.literal_eval or explicit logic.", conf=0.95, status="Confirmed"))
                if name.startswith(("subprocess.", "os.system")) and (name == "os.system" or any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in n.keywords)):
                    out.append(F(ln, line(ln), "Security", "HIGH", "Shell command execution", "Shell invocation may include user input.", "Command injection.", "Pass an argument list with shell=False.", "subprocess.run(['ls', path], check=True)", 0.8))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in n.args.defaults + [x for x in n.args.kw_defaults if x]:
                    if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                        out.append(F(d.lineno, line(d.lineno), "Bug", "MEDIUM", "Mutable default argument", "Default is shared across calls.", "State leaks between calls.", "Default to None and create inside.", "def f(x=None):\n    x = [] if x is None else x", 0.95, "Confirmed"))
                if len(n.body) == 1 and isinstance(n.body[0], ast.Pass) and n.body[0].lineno not in bad:
                    out.append(F(ln, line(ln), "Quality", "LOW", "Empty function", f"{n.name} does nothing.", "Dead/unfinished code.", "Implement or remove.", conf=0.9, status="Confirmed"))
                if len(n.body) > 60: out.append(F(ln, line(ln), "Maintainability", "LOW", "Very long function", f"{n.name} has {len(n.body)} statements.", "Hard to test.", "Split into smaller functions.", conf=0.7, status="Suggestion"))
            if isinstance(n, ast.ExceptHandler):
                if n.type is None: out.append(F(ln, line(ln), "Bug", "MEDIUM", "Bare except", "Catches everything incl. KeyboardInterrupt.", "Hides bugs.", "Catch specific exceptions.", "except ValueError as e:", 0.95, "Confirmed"))
                elif len(n.body) == 1 and isinstance(n.body[0], ast.Pass) and n.body[0].lineno not in bad: out.append(F(ln, line(ln), "Bug", "MEDIUM", "Exception silently ignored", "Handler does nothing.", "Failures unnoticed.", "Log or handle.", conf=0.9, status="Confirmed"))
            if isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True and not any(isinstance(x, (ast.Break, ast.Return)) for x in ast.walk(n)):
                out.append(F(ln, line(ln), "Bug", "MEDIUM", "Possible infinite loop", "while True with no break/return.", "Hang.", "Add exit condition.", conf=0.7))
        for nd in ast.walk(tree):
            for fld in ("body", "orelse", "finalbody"):
                seq = getattr(nd, fld, None)
                if isinstance(seq, list):
                    for a, b in zip(seq, seq[1:]):
                        if isinstance(a, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                            out.append(F(b.lineno, line(b.lineno), "Bug", "MEDIUM", "Unreachable code", "This statement follows return/raise/break/continue.", "It can never run.", "Remove it or fix the control flow.", conf=0.95, status="Confirmed")); break
            if isinstance(nd, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in nd.ops) and any(isinstance(c, ast.Constant) and c.value is None for c in nd.comparators):
                out.append(F(nd.lineno, line(nd.lineno), "Quality", "LOW", "Comparison to None with ==", "None should be compared by identity.", "A custom __eq__ can give wrong answers.", "Use `is None` / `is not None`.", "if x is None:", 0.9, "Confirmed"))
            if isinstance(nd, ast.Call) and isinstance(nd.func, ast.Attribute) and nd.func.attr == "run" and any(k.arg == "debug" and getattr(k.value, "value", None) is True for k in nd.keywords):
                out.append(F(nd.lineno, line(nd.lineno), "Security", "MEDIUM", "Debug mode enabled", "debug=True exposes an interactive debugger.", "Remote code execution if reachable.", "Disable debug outside local development.", "app.run(debug=False)", 0.85))
        withs = {id(i.context_expr) for w in ast.walk(tree) if isinstance(w, (ast.With, ast.AsyncWith)) for i in w.items}
        for nd in ast.walk(tree):
            if isinstance(nd, ast.Call) and isinstance(nd.func, ast.Name) and nd.func.id == "open" and id(nd) not in withs:
                out.append(F(nd.lineno, line(nd.lineno), "Bug", "LOW", "File opened without 'with'", "The file may not be closed on errors.", "Resource leak.", "Use a with-block.", "with open(path) as fh:\n    data = fh.read()", 0.7))
        from pytypes import check as type_check
        out += type_check(tree, lines)   # TypeError / AttributeError / wrong arguments, found by inferring types
        bad_text = "\n".join(lines[b - 1] for b in bad if 0 < b <= len(lines))
        try:
            from pyflakes.checker import Checker
            BUGS = {"ReturnOutsideFunction", "DuplicateArgument", "RaiseNotImplemented", "IsLiteral", "AssertTuple"}
            for m in sorted(Checker(tree, "submitted").messages, key=lambda m: m.lineno):
                kind, txt = type(m).__name__, m.message % m.message_args
                if bad and (kind != "UndefinedName" or re.search(r"\b" + re.escape(str(m.message_args[0])) + r"\b", bad_text)): continue   # near broken lines, only trust names that appear nowhere in them
                title = {"UndefinedName": "Undefined name", "UnusedImport": "Unused import", "UnusedVariable": "Unused variable"}.get(kind, re.sub(r"(?<!^)(?=[A-Z])", " ", kind))
                bug = kind == "UndefinedName" or kind in BUGS
                rec, fix = "Define, fix or remove it.", ""
                if kind == "UndefinedName":   # typo helper: 'nam' -> 'name'
                    nm = m.message_args[0]
                    known = {x.id for x in ast.walk(tree) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)} | {x.name for x in ast.walk(tree) if isinstance(x, (ast.FunctionDef, ast.ClassDef))} | {x.arg for x in ast.walk(tree) if isinstance(x, ast.arg)} | set(dir(builtins))
                    close = difflib.get_close_matches(nm, known, 1, 0.7)
                    if close: rec, fix = f"Did you mean '{close[0]}'?", re.sub(r"\b" + re.escape(nm) + r"\b", close[0], line(m.lineno).strip())
                out.append(F(m.lineno, line(m.lineno), "Bug" if bug else "Quality", "HIGH" if kind == "UndefinedName" else "MEDIUM" if bug else "LOW",
                             title, txt, "NameError at runtime: the program crashes on this line." if kind == "UndefinedName" else "Clutter or latent bug.", rec, fix, conf=0.9, status="Confirmed"))
        except ImportError: pass
        return out

class HTMLAnalyzer(HTMLParser):
    OPT_END = {"p", "li", "dt", "dd", "tr", "td", "th", "thead", "tbody", "tfoot", "option", "optgroup", "colgroup", "rt", "rp", "html", "head", "body"}
    VOID = {"meta","link","img","br","hr","input","area","base","col","embed","source","track","wbr","!doctype"}
    def analyze(self, src, lines):
        self.out, self.stack, self.src_lines = [], [], lines
        self.convert_charrefs = True; self.feed(src); self.close()
        for tag, ln in self.stack:
            if tag not in self.OPT_END: self.out.append(F(ln, lines[ln-1], "Bug", "MEDIUM", f"Unclosed <{tag}>", "No closing tag found.", "Broken layout.", "Close the tag.", conf=0.7))
        if "<html" in src.lower() and "lang=" not in src.lower(): self.out.append(F(1, "<html>", "Quality", "LOW", "Missing lang attribute", "Needed by screen readers.", "Accessibility.", "Add lang=\"en\".", conf=0.9, status="Confirmed"))
        return self.out + run_rules("html", src)
    def handle_starttag(self, tag, attrs):
        ln, a = self.getpos()[0], dict(attrs); code = self.src_lines[ln-1]
        if tag not in self.VOID: self.stack.append((tag, ln))
        if tag == "img" and "alt" not in a: self.out.append(F(ln, code, "Quality", "LOW", "Image missing alt text", "Accessibility.", "Screen readers can't describe it.", "Add alt.", conf=0.95, status="Confirmed"))
        if any(k.startswith("on") for k in a): self.out.append(F(ln, code, "Security", "LOW", "Inline event handler", "Blocks strict CSP.", "Weakens XSS defenses.", "Use addEventListener.", conf=0.8, status="Suggestion"))
        if tag == "a" and a.get("target") == "_blank" and "noopener" not in a.get("rel", ""): self.out.append(F(ln, code, "Security", "LOW", "target=_blank without rel=noopener", "Opened page can access window.opener.", "Tabnabbing.", "Add rel=\"noopener noreferrer\".", conf=0.8))
    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                for t, ln in self.stack[i + 1:]:
                    if t not in self.OPT_END: self.out.append(F(ln, self.src_lines[ln - 1], "Bug", "MEDIUM", f"Unclosed <{t}>", "It is still open when its parent closes.", "Broken layout.", "Close the tag.", conf=0.8))
                del self.stack[i:]; return
        self.out.append(F(self.getpos()[0], self.src_lines[self.getpos()[0] - 1], "Bug", "LOW", f"Unexpected </{tag}>", "This end tag has no matching start tag.", "Browsers ignore it; structure is likely wrong.", "Remove it or add the start tag.", conf=0.8))

def brace_check(lang, src):
    t, stack, bad = mask(src, lang), [], None
    for i, ch in enumerate(t):
        if ch == "{": stack.append(i)
        elif ch == "}":
            if stack: stack.pop()
            elif bad is None: bad = i
    pos = bad if bad is not None else (stack[-1] if stack else None)
    if pos is None: return []
    ln = t.count("\n", 0, pos) + 1
    return [F(ln, src.splitlines()[ln - 1], "Bug", "HIGH", "Unbalanced braces", "This brace has no matching partner.", "The code may not compile or parse.", "Match every opening and closing brace.", conf=0.85, status="Potential")]

def c_like_extras(lang, src, lines, unreachable=True):
    code, out = mask(src, lang).splitlines(), []
    if lang in ("javascript", "typescript"):
        full = "\n".join(code)
        for i, ln in enumerate(code, 1):
            for name in re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?:=|;|$)", ln):
                if len(re.findall(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", full)) == 1:
                    out.append(F(i, lines[i - 1], "Quality", "LOW", "Unused variable", f"'{name}' is declared but never used.", "Dead code.", "Remove it.", conf=0.7))
    for i in range(len(code) - 1 if unreachable else 0):
        a = code[i]
        if re.match(r"\s*(return|throw|break|continue)\b.*;\s*$", a):
            j = i + 1
            while j < len(code) and not code[j].strip(): j += 1
            if j < len(code) and len(code[j]) - len(code[j].lstrip()) == len(a) - len(a.lstrip()) \
               and not code[j].strip().startswith(("}", "case ", "default", "else", ")")):
                out.append(F(j + 1, lines[j], "Bug", "MEDIUM", "Unreachable code", "This statement follows return/throw/break/continue.", "It can never run.", "Remove it.", conf=0.8))
    return out

SYN = {"javascript": (["node", "--check"], ".js"), "bash": (["bash", "-n"], ".sh"), "php": (["php", "-l"], ".php"), "ruby": (["ruby", "-c"], ".rb")}

def syntax_check(lang, src, lines):
    """Real syntax check with the language's own parser when installed (parse only - code is never executed)."""
    cmd, ext = SYN.get(lang, (None, None))
    if not cmd or not shutil.which(cmd[0]): return []
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "code" + ext)
        with open(p, "w", encoding="utf-8") as fh: fh.write(src)
        try: r = subprocess.run(cmd + [p], capture_output=True, text=True, timeout=10)
        except Exception: return []
        out = ((r.stderr or "") + (r.stdout or "")).replace(d, "")
    if r.returncode == 0: return []
    m = re.search(r"(?:line |:)(\d+)", out)
    ln = min(max(int(m.group(1)), 1), max(len(lines), 1)) if m else 1
    msg = next((l.strip() for l in out.splitlines() if re.search("error", l, re.I)), "Syntax error")
    return [F(ln, lines[ln - 1] if lines else "", "Bug", "CRITICAL", "Syntax error", msg[:200], "Code will not run.", "Fix the syntax.", conf=1.0, status="Confirmed")]

def _analyze_core(lang, src):
    src = src.replace("\r\n", "\n").replace("\r", "\n")
    lines = src.splitlines()
    if lang == "python": found = PythonAnalyzer().analyze(src, lines)
    elif lang == "html": found = HTMLAnalyzer().analyze(src, lines)
    elif lang == "css":
        from css_analyzer import analyze_css
        found = analyze_css(src)[0] + run_rules(lang, src)
    elif lang in LANG_KEY:
        from parsing import all_syntax_errors, tree_checks
        found = run_rules(lang, src)
        errs, neutral = all_syntax_errors(lang, src)
        if errs is None:   # no real parser installed: weaker fallbacks
            syn = syntax_check(lang, src, lines)
            found += syn or (brace_check(lang, src) if lang == "css" or lang in BRACE else [])
            if lang in BRACE: found += c_like_extras(lang, src, lines)
        else:
            found += [F(ln, lines[ln - 1] if 0 < ln <= len(lines) else "", "Bug", "CRITICAL", "Syntax error", msg, "The code will not compile or run.", "Fix the syntax at this line.", conf=0.95, status="Confirmed") for ln, msg in errs]
            found += tree_checks(lang, neutral, lines, {ln for ln, _ in errs})
            if not errs and lang in ("javascript", "typescript"): found += c_like_extras(lang, src, lines, unreachable=False)
    else: raise ValueError("Unsupported language")
    return dedupe(found)

def dedupe(findings):
    seen, out = {}, []
    for f in findings:
        k = (f["line_number"], f["title"])
        if k not in seen: seen[k] = f; out.append(f)
        elif f["confidence"] > seen[k]["confidence"]: out[out.index(seen[k])] = seen[k] = f
    return sorted(out, key=lambda f: (-ORDER.index(f["severity"]), f["line_number"] or 0))

def score(findings):
    def s(cats):
        cost = sum(SEV[f["severity"]] * STATUS.get(f["status"], .6) for f in findings if cats is None or f["category"] in cats)
        return max(0, round(100 - cost))
    return dict(overall=s(None), security=s({"Security"}), quality=s({"Quality", "Performance"}),
                maintainability=s({"Maintainability", "Quality"}), reliability=s({"Bug"}))

def label(n): return "Excellent" if n >= 90 else "Good" if n >= 75 else "Needs Improvement" if n >= 60 else "Poor" if n >= 40 else "Critical"


def analyze_code(lang, src, debug=None):
    """Static analysis + (when the language's compiler is installed) the compiler's own errors. `debug`, if given, receives diagnostics info."""
    found = _analyze_core(lang, src)
    try:
        from services.toolchain import diagnostics
        diags, info = diagnostics(lang, src.replace("\r\n", "\n").replace("\r", "\n"))
    except Exception as e:   # a broken toolchain must never break the review
        diags, info = [], {"ran": False, "skipped": f"toolchain error: {type(e).__name__}"}
    if debug is not None: debug["compiler"] = info
    lines = src.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    if any(d["sev"] == "error" for d in diags): found = [f for f in found if f["title"] != "Syntax error"]   # the compiler is authoritative
    for d in diags:
        err = d["sev"] == "error"; ln = d["line"]
        found.append(F(ln, lines[ln - 1] if 0 < ln <= len(lines) else "", "Bug", "CRITICAL" if err else "LOW", f"Compiler {'error' if err else 'warning'}: {d['msg'][:70]}", d["msg"],
                       "The compiler rejects this code." if err else "The compiler flags this line.", "Fix it as the compiler message says.", conf=0.99, status="Confirmed"))
    return dedupe(found)


NUMBERED = [re.compile(p) for p in (r"^[ \t]*(\d{1,6})\.(?: |\t|$)", r"^[ \t]*(\d{1,6})\)(?: |\t|$)", r"^[ \t]*(\d{1,6}):(?: |\t|$)", r"^[ \t]*(\d{1,6})[ \t]*\|(?: |\t|$)", r"^[ \t]*(\d{1,6})\t")]

def strip_line_numbers(src):
    """Code copied from tutorials/chats often starts every line with its number ("1. x = 1"). If almost every line does, and the numbers
    count up by one, they are not code: remove them (indentation is kept). Returns (code, note); note is "" when nothing was removed."""
    lines = src.split("\n"); body = [l for l in lines if l.strip()]
    if len(body) < 3: return src, ""
    for rx in NUMBERED:
        hits = [int(m.group(1)) for m in (rx.match(l) for l in lines) if m]
        if len(hits) < 3 or len(hits) < 0.8 * len(body): continue
        if sum(1 for x, y in zip(hits, hits[1:]) if y == x + 1) < 0.8 * (len(hits) - 1): continue
        return "\n".join(rx.sub("", l, count=1) for l in lines), "Line numbers at the start of your lines (like '1.') were ignored; line numbers in this report match your lines."
    return src, ""
