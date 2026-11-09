"""Runs submitted code in ANY supported language (compiling first where needed) and captures its output.
NOT a hardened sandbox: the code can read files and use the network. Enabled only when ENABLE_CODE_EXECUTION=true
(default: on only if FLASK_ENV=development) and never on public hosting. HTML and CSS are shown as sandboxed previews."""
import os, tempfile
from services import toolchain

def enabled():
    if os.getenv("VERCEL") or os.getenv("RENDER"): return False   # never run visitor code on a public deployment: it could read the function's secrets
    v = (os.getenv("ENABLE_CODE_EXECUTION") or "").lower()
    return v == "true" or (v == "" and os.getenv("FLASK_ENV") == "development")

def css_demo(css):
    css = css.replace("</style", "<\\/style")   # cannot break out of the <style> element
    return ('<!doctype html><meta charset="utf-8"><title>CSS preview</title><style>' + css + '</style><body><div class="container"><header><nav><a href="#">Home</a> <a href="#">About</a></nav>'
            '<h1>Heading 1</h1></header><main><h2>Heading 2</h2><p>A paragraph with <a href="#">a link</a>, <strong>bold</strong> and <em>italic</em> text.</p>'
            '<button class="btn">Button</button> <input placeholder="Input"><ul><li>List item one</li><li>List item two</li></ul>'
            '<table><tr><th>Name</th><th>Value</th></tr><tr><td>Row</td><td>1</td></tr></table></main><footer>Footer</footer></div></body>')

def run_code(lang, src, timeout=5):
    if lang == "html": return {"kind": "preview"}
    if lang == "css": return {"kind": "preview", "html": css_demo(src)}
    if lang not in toolchain.NAMES: return {"kind": "unsupported", "message": f"Running {lang} is not supported."}
    if not enabled(): return {"kind": "disabled", "message": "Running code is disabled on this deployment for security." if toolchain.hosted() else "Code execution is turned off. Set ENABLE_CODE_EXECUTION=true in .env to enable it (only on a machine you trust)."}
    with tempfile.TemporaryDirectory() as d:
        steps, missing = toolchain.plan(lang, d, src)
        if missing: return {"kind": "missing", "message": f"Running {toolchain.NAMES[lang]} needs {missing[0]} on this computer. {missing[1]}".strip()}
        return toolchain.run_steps(steps, d, timeout)
