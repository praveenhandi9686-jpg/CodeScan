"""Conservative, deterministic auto-fixes. Rules only match real code (strings/comments are masked)."""
import ast, re
from analyzers import mask

def _line(s, pos):
    a = s.rfind("\n", 0, pos) + 1; b = s.find("\n", pos)
    return s[a:b if b != -1 else len(s)]

def _apply(src, lang, rx, fn):
    n, edits = 0, []
    for m in re.compile(rx).finditer(mask(src, lang, lang == "html" and False)):
        rep = fn(m, src)
        if rep is not None: edits.append((m.start(), m.end(), rep))
    for a, b, rep in reversed(edits): src = src[:a] + rep + src[b:]
    return src, len(edits)

T = lambda m, s, i: s[m.start(i):m.end(i)]
SECRET = r"(?im)^([ \t]*)(?=\w*(?:password|passwd|secret|api[_-]?key|token))([A-Za-z_]\w*)[ \t]*=[ \t]*([\"'])[^\"'\n]{4,}\3"
RULES = {
 "python": [("Replaced bare `except:` with `except Exception:`", r"\bexcept\s*:", lambda m, s: "except Exception:"),
   ("Compared to None with `is` / `is not`", r"(==|!=)\s*None\b", lambda m, s: "is None" if m.group(1) == "==" else "is not None"),
   ("Switched yaml.load to yaml.safe_load", r"\byaml\.load\((?![^)]*Loader)", lambda m, s: "yaml.safe_load("),
   ("Enabled TLS verification", r"\bverify\s*=\s*False", lambda m, s: "verify=True"),
   ("Turned off debug mode", r"\bdebug\s*=\s*True", lambda m, s: "debug=False"),
   ("Moved hardcoded secret to an environment variable", SECRET, lambda m, s: f'{T(m, s, 1)}{T(m, s, 2)} = os.environ.get("{T(m, s, 2).upper()}", "")')],
 "js": [("Replaced var with let", r"(?<![\w$.])var\s+", lambda m, s: "let "),
   ("Used strict equality (===, !==)", r"(?<![=!<>])==(?!=)(?!\s*(?:null|undefined)\b)|(?<![=!])!=(?!=)(?!\s*(?:null|undefined)\b)", lambda m, s: "===" if m.group(0) == "==" else "!=="),
   ("Logged errors in empty catch blocks", r"catch\s*\((\w+)\)\s*\{\s*\}", lambda m, s: f"catch ({T(m, s, 1)}) {{ console.error({T(m, s, 1)}); }}"),
   ("Used textContent instead of innerHTML for plain text", r"\.innerHTML\s*=", lambda m, s: None if "<" in _line(s, m.start()) else ".textContent =")],
 "html": [("Added empty alt text to images", r"<img\b(?![^>]*\balt\s*=)([^>]*?)(\s*/?)>", lambda m, s: f'<img{T(m, s, 1)} alt=""{T(m, s, 2)}>'),
   ("Added lang attribute to <html>", r"<html\b(?![^>]*\blang\s*=)", lambda m, s: '<html lang="en"'),
   ("Added rel=noopener to target=_blank links", r"<a\b(?![^>]*\brel\s*=)([^>]*\btarget\s*=\s*[\"']_blank[\"'][^>]*)>", lambda m, s: f'<a{T(m, s, 1)} rel="noopener noreferrer">')],
 "css": [("Removed empty rules", r"[^{}]+\{\s*\}\s*", lambda m, s: "")],
 "bash": [("Replaced chmod 777 with 755", r"\bchmod\s+(-R\s+)?777\b", lambda m, s: "chmod " + (T(m, s, 1) if m.group(1) else "") + "755")],
 "java": [("Used .equals() for string comparison", r"(\b\w+)\s*(==|!=)\s*(\"[^\"\n]*\")", lambda m, s: ("!" if m.group(2) == "!=" else "") + f"{T(m, s, 3)}.equals({T(m, s, 1)})")],
 "c": [("Replaced gets() with fgets()", r"\bgets\s*\(\s*(\w+)\s*\)", lambda m, s: f"fgets({T(m, s, 1)}, sizeof({T(m, s, 1)}), stdin)")],
 "php": [("Escaped echoed request data", r"\becho\s+(\$_(?:GET|POST|REQUEST)\[[^\]]*\])\s*;", lambda m, s: f"echo htmlspecialchars({T(m, s, 1)}, ENT_QUOTES);")],
}
RULES["typescript"] = RULES["js"]; RULES["javascript"] = RULES["js"]; RULES["cpp"] = RULES["c"]

def _py_mutable(src):
    try: tree = ast.parse(src)
    except SyntaxError: return src, 0
    lines, ins, n = src.split("\n"), [], 0
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
        a = fn.args
        pairs = list(zip(a.args[len(a.args) - len(a.defaults):], a.defaults)) + [(k, d) for k, d in zip(a.kwonlyargs, a.kw_defaults) if d]
        bad = [(g, d) for g, d in pairs if isinstance(d, (ast.List, ast.Dict, ast.Set)) and d.lineno == d.end_lineno]
        first = fn.body[0]
        if not bad or first.lineno == fn.lineno: continue
        doc = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
        ind = re.match(r"\s*", lines[first.lineno - 1]).group(0)
        guard = []
        for g, d in sorted(bad, key=lambda p: (p[1].lineno, p[1].col_offset), reverse=True):
            b = lines[d.lineno - 1].encode()
            lines[d.lineno - 1] = (b[:d.col_offset] + b"None" + b[d.end_col_offset:]).decode()
            guard = [f"{ind}if {g.arg} is None:", f"{ind}    {g.arg} = {ast.get_source_segment(src, d)}"] + guard
        ins.append((first.end_lineno if doc else first.lineno - 1, guard)); n += len(bad)
    for idx, g in sorted(ins, key=lambda t: t[0], reverse=True): lines[idx:idx] = g
    return "\n".join(lines), n

def auto_fix(lang, src):
    """Returns (fixed_source, [human-readable change descriptions])."""
    src = src.replace("\r\n", "\n").replace("\r", "\n"); orig, changes = src, []
    try:
        if lang == "css":
            from css_analyzer import css_fix
            src, ch = css_fix(src); changes += ch
        for desc, rx, fn in RULES.get(lang, []):
            src, n = _apply(src, lang, rx, fn)
            if n: changes.append(f"{desc} ({n}x)" if n > 1 else desc)
        if lang == "python":
            src, n = _py_mutable(src)
            if n: changes.append(f"Fixed mutable default argument ({n}x)" if n > 1 else "Fixed mutable default argument")
            if "os.environ.get(" in src and not re.search(r"^\s*(import os\b|from os\b)", src, re.M): src = "import os\n" + src
            ast.parse(src)
    except Exception:
        return orig, []
    return src, changes
