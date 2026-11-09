"""Real parsers (tree-sitter) for exact syntax errors, exact comment/string masking and AST checks.
Grammars are optional: if one is missing, callers fall back to the pattern-based engine."""
import ast, functools, importlib, re, warnings
try:
    from tree_sitter import Language, Parser
except ImportError:
    Language = Parser = None

GRAMMARS = {"python": ("tree_sitter_python", "language"), "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"), "java": ("tree_sitter_java", "language"),
    "c": ("tree_sitter_c", "language"), "cpp": ("tree_sitter_cpp", "language"), "csharp": ("tree_sitter_c_sharp", "language"),
    "go": ("tree_sitter_go", "language"), "php": ("tree_sitter_php", "language_php"), "ruby": ("tree_sitter_ruby", "language"),
    "rust": ("tree_sitter_rust", "language"), "bash": ("tree_sitter_bash", "language"),
    "kotlin": ("tree_sitter_kotlin", "language"), "swift": ("tree_sitter_swift", "language")}
_parsers = {}

def get_parser(lang):
    if lang not in _parsers:
        p = None
        if Parser and lang in GRAMMARS:
            try:
                mod, fn = GRAMMARS[lang]; p = Parser(Language(getattr(importlib.import_module(mod), fn)()))
            except Exception: p = None
        _parsers[lang] = p
    return _parsers[lang]

@functools.lru_cache(maxsize=8)
def parse(lang, src):
    p = get_parser(lang)
    if not p: return None, None
    b = src.encode("utf-8"); return p.parse(b).root_node, b

def walk(root):
    st = [root]
    while st:
        n = st.pop(); yield n; st.extend(reversed(n.children))

def engine_for(lang):
    if lang == "python": return "Python ast (exact)"
    if lang == "css": return "CSS parser (exact)"
    if lang == "html": return "HTML parser"
    return "tree-sitter (exact)" if get_parser(lang) else "pattern rules only (install tree-sitter packages)"

def ts_mask(lang, src, blank_strings=True):
    """Blank comments and string contents using the real syntax tree. Keeps length and line breaks (1:1 offsets)."""
    root, b = parse(lang, src)
    if root is None: return None
    spans, st = [], [root]
    while st:
        n = st.pop(); t = n.type
        if "comment" in t: spans.append((n.start_byte, n.end_byte, "c")); continue
        if any(k in t for k in ("string", "heredoc", "nowdoc", "regex", "char_literal", "character_literal", "rune")):
            spans.append((n.start_byte, n.end_byte, "s")); continue
        st.extend(n.children)
    spans.sort(); out, pos = [], 0
    for a, e, kind in spans:
        if a < pos: continue
        out.append(b[pos:a].decode("utf-8", "replace"))
        seg = b[a:e].decode("utf-8", "replace"); blank = re.sub(r"[^\n]", " ", seg); q = re.match(r"[A-Za-z]{0,3}[\"'`]", seg)
        if kind == "s" and not blank_strings: out.append(seg)
        elif kind == "s" and q and len(seg) > q.end(): out.append(seg[:q.end()] + blank[q.end():-1] + seg[-1])
        else: out.append(blank)
        pos = e
    out.append(b[pos:].decode("utf-8", "replace")); return "".join(out)

def syntax_errors(lang, src, limit=5):
    """None = no parser available. Otherwise [(line, message)] of real syntax errors."""
    root, b = parse(lang, src)
    if root is None: return None
    if not root.has_error: return []
    found, st = set(), [root]
    while st:
        n = st.pop()
        if not (n.has_error or n.is_missing): continue
        if n.is_missing: found.add((n.start_point[0] + 1, f"Missing '{n.type}'")); continue
        if n.type == "ERROR":
            leaf = n
            while leaf.children: leaf = leaf.children[0]
            tok = b[leaf.start_byte:leaf.end_byte].decode("utf-8", "replace").strip()[:30]
            found.add((n.start_point[0] + 1, f"Unexpected '{tok}'" if tok and n.start_point[0] == n.end_point[0] else "Invalid or incomplete statement")); continue
        st.extend(reversed(n.children))
    return sorted(found)[:limit]

def first_error(lang, src):
    """(line, message) of the first syntax error, else None. Python uses CPython itself for exact messages."""
    if lang == "python":
        try:
            with warnings.catch_warnings(): warnings.simplefilter("ignore"); ast.parse(src)
            return None
        except SyntaxError as e: return (e.lineno or 1, e.msg or "invalid syntax")
        except ValueError: return (1, "source contains null bytes")
    errs = syntax_errors(lang, src, limit=50)
    return errs[0] if errs else None

def _depths(masked, lang):
    opens, closes = ("([{", ")]}") if lang == "python" else ("([", ")]")
    d, at = 0, []
    for ln in masked.split("\n"):
        at.append(d)
        for ch in ln:
            if ch in opens: d += 1
            elif ch in closes: d = max(0, d - 1)
    return at, d

def neutralize(lang, src, line, msg):
    """Replace the broken statement by a harmless one, keeping the line count, so parsing can continue to the next error."""
    from analyzers import mask
    lines = src.split("\n"); n = len(lines); i = min(max(line, 1), n) - 1
    at, final = _depths(mask(src, lang), lang)
    end_depth = lambda k: at[k + 1] if k + 1 < n else final
    s = i
    while s > 0 and at[s] > 0: s -= 1            # error inside a multi-line bracket: take the whole statement
    e = i
    while e < n - 1 and end_depth(e) > 0 and e - i < 60: e += 1
    if end_depth(e) > 0: e = i                   # bracket never closes: only the reported line
    ind = lambda t: re.match(r"[ \t]*", t).group(0)
    if lang == "python":
        prev = next((l for l in reversed(lines[:s]) if l.strip()), ""); m = msg.lower()
        if "expected an indented block" in m: first = ind(prev) + "    pass"
        elif "indent" in m: first = ind(prev) + "pass"
        else:
            nxt = next((l for l in lines[e + 1:] if l.strip()), "")
            header = len(ind(nxt).expandtabs(8)) > len(ind(lines[s]).expandtabs(8))
            first = ind(lines[s]) + ("if 1:" if header else "pass")
        for k in range(s, e + 1): lines[k] = first if k == s else ""
    else:
        for k in range(s, e + 1): lines[k] = re.sub(r"[^{};\s]", " ", lines[k])   # keep braces so blocks stay balanced
    return "\n".join(lines)

def all_syntax_errors(lang, src, limit=50):
    """EVERY syntax error, not just the first. Returns (errors, neutral_source); errors is None when no parser exists."""
    if lang != "python" and get_parser(lang) is None: return None, src
    errs, seen, cur = [], set(), src
    for _ in range(limit):
        e = first_error(lang, cur)
        if not e: break
        line, msg = e
        if line not in seen: seen.add(line); errs.append((line, msg[:1].upper() + msg[1:]))
        nxt = neutralize(lang, cur, line, msg)
        if nxt == cur: break
        cur = nxt
    return errs, cur

TERM = {"return_statement", "throw_statement", "break_statement", "continue_statement", "return", "break", "next", "jump_expression",
        "control_transfer_statement", "return_expression", "break_expression", "continue_expression", "throw_expression"}
SKIP = {"function_declaration", "function_definition", "method_declaration", "class_declaration", "generator_function_declaration",
        "labeled_statement", "case_statement", "switch_case", "switch_default", "default_case", "else_clause", "catch_clause",
        "finally_clause", "preproc_else", "preproc_elif", "ERROR"}
BLOCKS = {"statement_block", "block", "compound_statement", "declaration_list"}
CODE_LOOPS = {"javascript", "typescript", "java", "c", "cpp", "csharp", "php"}

def tree_checks(lang, src, lines, bad=()):
    """AST-based findings (only run on code that parses cleanly)."""
    from analyzers import F
    root, b = parse(lang, src)
    if root is None or root.has_error: return []
    txt = lambda n: b[n.start_byte:n.end_byte].decode("utf-8", "replace")
    line = lambda n: lines[n.start_point[0]] if n.start_point[0] < len(lines) else ""
    out = []
    touched = lambda n: any(n.start_point[0] + 1 <= x <= n.end_point[0] + 1 for x in bad)   # skip code we had to neutralise
    for n in walk(root):
        kids = [c for c in n.named_children if "comment" not in c.type]
        for a, nxt in zip(kids, kids[1:]):
            x = a.named_children[0] if a.type == "expression_statement" and a.named_child_count == 1 else a
            if x.type in TERM and nxt.type not in SKIP and not touched(a) and not touched(nxt):
                out.append(F(nxt.start_point[0] + 1, line(nxt), "Bug", "MEDIUM", "Unreachable code", "This statement follows return/throw/break/continue.", "It can never run.", "Remove it or fix the control flow.", conf=0.9, status="Confirmed")); break
        if n.type in ("catch_clause", "catch_block"):
            body = n.child_by_field_name("body") or (n.named_children[-1] if n.named_children else None)
            if body is not None and body.type in BLOCKS and not touched(n) and not [c for c in body.named_children if "comment" not in c.type]:
                out.append(F(n.start_point[0] + 1, line(n), "Bug", "MEDIUM", "Empty catch block", "The exception is swallowed silently.", "Failures go unnoticed.", "Handle or log the error.", conf=0.95, status="Confirmed"))
        if lang in CODE_LOOPS and n.type in ("if_statement", "while_statement", "do_statement") and not touched(n):
            cond = n.child_by_field_name("condition")
            if cond is not None and cond.type == "parenthesized_expression" and cond.named_children and cond.named_children[0].type == "assignment_expression":
                out.append(F(n.start_point[0] + 1, line(n), "Bug", "MEDIUM", "Assignment used as condition", "'=' assigns; '==' compares.", "The branch depends on the assigned value, usually a typo.", "Use == / === or add extra parentheses if intended.", conf=0.8))
        if lang in CODE_LOOPS and n.type in ("while_statement", "do_statement", "for_statement") and not touched(n):
            cond = n.child_by_field_name("condition")
            forever = (n.type == "for_statement" and (cond is None or cond.type == "empty_statement")) or (cond is not None and txt(cond).strip().lower() in ("(true)", "(1)"))
            if forever and not any(d.type in ("break_statement", "return_statement", "throw_statement") for d in walk(n)):
                out.append(F(n.start_point[0] + 1, line(n), "Bug", "MEDIUM", "Possible infinite loop", "The loop condition is always true and nothing inside exits it.", "The program may hang.", "Add an exit condition.", conf=0.7))
    return out
