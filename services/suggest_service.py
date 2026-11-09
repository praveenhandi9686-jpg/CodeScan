"""Builds the 'Suggested Code' for a review: deterministic fixes, optionally upgraded by the AI.
The AI version is only used if static analysis rates it at least as good as the automatic fixes."""
import difflib, re
from analyzers import analyze_code, score
from fixer import auto_fix
from services.ai_client import chat, configured, AIError

PROMPT = """Rewrite the following {lang} code so that every listed issue is fixed. Keep behaviour, names and structure; do not add features.
Output exactly one fenced code block with the complete corrected code, then a line "CHANGES:" followed by up to 8 short bullet lines.
ISSUES:
{issues}
CODE:
{code}"""

def _rank(lang, code):
    f = analyze_code(lang, code); sc = score(f)["overall"]
    return (any(x["title"] == "Syntax error" for x in f), -sc), f, sc

def build_suggestion(lang, src, findings):
    src = src.replace("\r\n", "\n")
    base, _, before = _rank(lang, src)
    best, changes = auto_fix(lang, src)
    source, note = "auto-fix", ""
    if configured() and findings:
        try:
            issues = "\n".join(f"- line {f['line_number']}: {f['title']}" for f in findings[:25])
            text = chat(PROMPT.format(lang=lang, issues=issues, code=src), max_tokens=6000, timeout=90)
            m = re.search(r"```[\w+#.-]*\n(.*?)```", text, re.S)
            if m and m.group(1).strip():
                cand = m.group(1).rstrip("\n") + "\n"
                if _rank(lang, cand)[0] <= _rank(lang, best)[0]:
                    best, source = cand, "ai"
                    if "CHANGES:" in text: changes = [l.strip("-*• ").strip() for l in text.split("CHANGES:", 1)[1].splitlines() if l.strip()][:8]
                else: note = "The AI's version scored worse in static analysis, so the automatic fixes are shown instead."
            else: note = "The AI reply contained no code block."
        except AIError as e: note = f"AI suggestion unavailable: {e}"
    _, after_f, after = _rank(lang, best)
    diff = "".join(difflib.unified_diff(src.splitlines(True), best.splitlines(True), "original", "suggested", n=2))
    return dict(code=best, source=source, changes=changes, diff=diff, score_before=before, score_after=after,
                remaining=[f["title"] for f in after_f][:10], note=note, unchanged=best.strip() == src.strip())
