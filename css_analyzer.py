"""CSS analyzer built on a small tokenizer/scanner (not line regexes): tracks blocks, nested/at-rules,
declarations, strings and comments. Returns (findings, fix_edits)."""
import bisect, difflib, re

PROPS = set("""align-content align-items align-self all animation animation-delay animation-direction animation-duration animation-fill-mode
animation-iteration-count animation-name animation-play-state animation-timing-function appearance aspect-ratio backdrop-filter backface-visibility
background background-attachment background-blend-mode background-clip background-color background-image background-origin background-position
background-position-x background-position-y background-repeat background-size block-size border border-block border-bottom border-bottom-color
border-bottom-left-radius border-bottom-right-radius border-bottom-style border-bottom-width border-collapse border-color border-image
border-image-outset border-image-repeat border-image-slice border-image-source border-image-width border-inline border-left border-left-color
border-left-style border-left-width border-radius border-right border-right-color border-right-style border-right-width border-spacing border-style
border-top border-top-color border-top-left-radius border-top-right-radius border-top-style border-top-width border-width bottom box-shadow
box-sizing break-after break-before break-inside caption-side caret-color clear clip clip-path color color-scheme column-count column-fill column-gap
column-rule column-rule-color column-rule-style column-rule-width column-span column-width columns contain container container-name container-type
content counter-increment counter-reset cursor direction display empty-cells fill filter flex flex-basis flex-direction flex-flow flex-grow flex-shrink
flex-wrap float font font-display font-family font-feature-settings font-kerning font-size font-size-adjust font-stretch font-style font-synthesis
font-variant font-variant-caps font-variant-numeric font-weight gap grid grid-area grid-auto-columns grid-auto-flow grid-auto-rows grid-column
grid-column-end grid-column-gap grid-column-start grid-gap grid-row grid-row-end grid-row-gap grid-row-start grid-template grid-template-areas
grid-template-columns grid-template-rows height hyphens image-rendering inherits initial-value inline-size inset inset-block inset-inline isolation
justify-content justify-items justify-self left letter-spacing line-break line-height list-style list-style-image list-style-position list-style-type
margin margin-block margin-bottom margin-inline margin-left margin-right margin-top mask mask-image mask-position mask-repeat mask-size max-block-size
max-height max-inline-size max-width min-block-size min-height min-inline-size min-width mix-blend-mode object-fit object-position offset opacity
order orphans outline outline-color outline-offset outline-style outline-width overflow overflow-anchor overflow-wrap overflow-x overflow-y
overscroll-behavior padding padding-block padding-bottom padding-inline padding-left padding-right padding-top page-break-after page-break-before
page-break-inside paint-order perspective perspective-origin place-content place-items place-self pointer-events position quotes resize right rotate
row-gap scale scroll-behavior scroll-margin scroll-padding scroll-snap-align scroll-snap-type scrollbar-color scrollbar-width shape-outside size src
stroke stroke-width syntax tab-size table-layout text-align text-align-last text-decoration text-decoration-color text-decoration-line
text-decoration-style text-decoration-thickness text-indent text-justify text-overflow text-shadow text-size-adjust text-transform text-underline-offset
text-wrap top touch-action transform transform-origin transform-style transition transition-delay transition-duration transition-property
transition-timing-function translate unicode-bidi unicode-range user-select vertical-align view-transition-name visibility white-space widows width
will-change word-break word-spacing word-wrap writing-mode z-index zoom accent-color""".split())
LENGTH = set("""width height min-width max-width min-height max-height margin margin-top margin-right margin-bottom margin-left padding padding-top
padding-right padding-bottom padding-left top right bottom left font-size gap row-gap column-gap border-width border-top-width border-right-width
border-bottom-width border-left-width border-radius letter-spacing word-spacing text-indent outline-width outline-offset""".split())
GROUPS = {"media", "supports", "layer", "container", "keyframes", "-webkit-keyframes", "-moz-keyframes", "document", "scope", "starting-style"}
HPAD = ("padding", "padding-left", "padding-right", "border", "border-left", "border-right", "border-width", "border-left-width", "border-right-width")

def analyze_css(src):
    from analyzers import mask, F
    src = src.replace("\r\n", "\n").replace("\r", "\n")
    t = mask(src, "css")   # comments blanked, string contents blanked, offsets preserved
    t = re.sub(r"url\(\s*[^)'\"\s][^)]*\)", lambda m: "url(" + " " * (len(m.group(0)) - 5) + ")", t)
    starts, lines = [0] + [i + 1 for i, c in enumerate(t) if c == "\n"], src.split("\n")
    ln = lambda p: bisect.bisect_right(starts, p)
    out, edits, pending, seen, seq, state, stack = [], [], [], set(), [0], {"bb": False}, []

    def add(pos, sev, title, why, imp, rec, fix="", cat="Bug", conf=0.9, status="Confirmed"):
        n = min(ln(pos), len(lines)); out.append(F(n, lines[n - 1], cat, sev, title, why, imp, rec, fix, conf, status))
    def edit(pos, text, desc): seq[0] += 1; edits.append((pos, seq[0], text, desc))

    def one(a, b, terminated):
        raw = t[a:b]; d = raw.strip()
        if not d: return
        off, blk = a + len(raw) - len(raw.lstrip()), stack[-1]
        colon = d.find(":")
        if colon == -1:
            return add(off, "HIGH", "Invalid declaration", f"'{d[:40]}' has no ':' between property and value.", "Browsers drop this declaration.", "Write it as property: value;")
        prop, val = d[:colon].strip().lower(), d[colon + 1:].strip()
        if not terminated:
            add(off + len(d) - 1, "LOW", "Missing trailing semicolon", f"'{prop}' is the last declaration and has no ';'.", "Adding a property below it later breaks both.", "End every declaration with ';'.", cat="Quality")
            edit(off + len(d), ";", "Added missing semicolons")
        if not re.fullmatch(r"-{0,2}[a-z_][\w-]*", prop):
            return add(off, "HIGH", "Invalid property name", f"'{prop[:40]}' is not a valid property name.", "The declaration is ignored.", "Fix the property name.")
        if not (prop in PROPS or prop.startswith("-")):
            close = difflib.get_close_matches(prop, PROPS, 1, 0.8)
            if close: add(off, "MEDIUM", "Unknown property", f"'{prop}' is not a CSS property. Did you mean '{close[0]}'?", "The declaration is ignored.", f"Use '{close[0]}'.", f"{close[0]}: {val};")
            else: add(off, "LOW", "Unrecognized property", f"'{prop}' is not a standard property.", "It may be ignored by browsers.", "Check the spelling and browser support.", conf=0.6, status="Potential")
        if not val: add(off, "HIGH", "Empty value", f"'{prop}' has no value.", "The declaration is ignored.", "Give it a value.")
        else:
            if val.count("(") != val.count(")"): add(off, "HIGH", "Unbalanced parentheses", f"The value of '{prop}' has mismatched parentheses.", "The declaration is ignored.", "Balance the parentheses.")
            for h in re.findall(r"#([0-9A-Za-z]+)", val):
                if len(h) not in (3, 4, 6, 8) or re.search(r"[^0-9a-fA-F]", h): add(off, "HIGH", "Invalid hex color", f"'#{h}' is not a valid color.", "The declaration is ignored.", "Use 3, 4, 6 or 8 hex digits.")
            if prop in LENGTH and "(" not in val:
                for x in re.finditer(r"(?<![\w.#%-])(\d*\.?\d+)(?![\w%.])", val):
                    if float(x.group(1)) != 0: add(off, "MEDIUM", "Missing unit", f"'{x.group(1)}' in '{prop}' needs a unit such as px, em or %.", "Browsers ignore unitless non-zero lengths.", "Add a unit.", f"{prop}: {x.group(1)}px;"); break
            if "!important" in val.lower(): add(off, "LOW", "!important used", "!important overrides the normal cascade.", "Hard to maintain.", "Fix selector specificity instead.", cat="Quality", conf=0.8, status="Suggestion")
        if blk["props"].get(prop) == val: add(off, "LOW", "Duplicate property", f"'{prop}: {val}' is declared twice in this rule.", "Redundant code.", "Remove the duplicate.", cat="Quality")
        blk["props"][prop] = val; blk["pos"][prop] = off
        blk["last"] = ((b + 1 if terminated and t[b:b + 1] == ";" else off + len(d)), re.match(r"[ \t]*", lines[min(ln(off), len(lines)) - 1]).group(0))

    def decl(a, b, terminated):
        seg, colon = t[a:b], t[a:b].find(":")
        if colon != -1:
            for m in re.finditer(r"\s+(-{0,2}[a-zA-Z][\w-]*)\s*:(?!:)", seg[colon + 1:]):
                nm = m.group(1).lower()
                if nm in PROPS or nm.startswith("-"):
                    cut = a + colon + 1 + m.start()
                    add(cut - 1, "HIGH", "Missing semicolon", f"A ';' is missing before '{nm}'.", "The browser reads both properties as one invalid declaration and ignores them.", "End the previous declaration with ';'.", conf=0.95)
                    edit(cut, ";", "Added missing semicolons")
                    one(a, cut, True); return decl(cut, b, terminated)
        one(a, b, terminated)

    def close(blk):
        if blk["kind"] != "rule": return
        p = blk["props"]
        if not p and not blk["nested"]: add(blk["ps"], "LOW", "Empty rule", f"'{blk['sel']}' has no declarations.", "Dead code.", "Remove the rule or add styles.", cat="Quality")
        if p.get("box-sizing") == "border-box" and re.search(r"\*|(^|,)\s*(html|:root|body)\s*($|,)", blk["sel"]): state["bb"] = True
        if p.get("width", "").replace(" ", "") == "100%" and "box-sizing" not in p and blk["last"] and any(k in p and re.search(r"[1-9]", p[k]) for k in HPAD):
            pending.append((blk["pos"]["width"], blk["last"]))

    i, seg, n = 0, 0, len(t)
    while i < n:
        c = t[i]
        if c in "\"'":
            j, nl = t.find(c, i + 1), t.find("\n", i + 1)
            if j == -1 or (nl != -1 and nl < j): add(i, "HIGH", "Unterminated string", "A quote is opened but never closed on this line.", "The rest of the declaration is ignored.", "Close the string.")
            else: i = j
        elif c == "{":
            raw = t[seg:i]; prelude = re.sub(r"\s+", " ", raw.strip()); ps = seg + len(raw) - len(raw.lstrip())
            kind = "rule"
            if prelude.startswith("@"):
                nm = re.match(r"@([\w-]+)", prelude); kind = "group" if nm and nm.group(1).lower() in GROUPS else "decl"
            else:
                if not prelude: add(i, "HIGH", "Missing selector", "A block has no selector.", "The whole block is ignored.", "Add a selector before '{'.")
                key = tuple(b["sel"] for b in stack) + (prelude,)
                if prelude and key in seen: add(ps, "LOW", "Duplicate selector", f"'{prelude[:40]}' is defined more than once.", "Rules are harder to maintain.", "Merge the rules.", cat="Quality", conf=0.7, status="Suggestion")
                seen.add(key)
            if stack: stack[-1]["nested"] = True
            stack.append(dict(kind=kind, sel=prelude, ps=ps, props={}, pos={}, nested=False, last=None)); seg = i + 1
        elif c == ";":
            if stack and stack[-1]["kind"] != "group": decl(seg, i, True)
            seg = i + 1
        elif c == "}":
            if not stack: add(i, "HIGH", "Unexpected closing brace", "This '}' has no matching '{'.", "Following rules may be ignored.", "Remove it or add the missing '{'.")
            else:
                blk = stack[-1]
                if blk["kind"] != "group" and t[seg:i].strip(): decl(seg, i, False)
                close(stack.pop())
            seg = i + 1
        i += 1
    for blk in stack: add(blk["ps"], "HIGH", "Unclosed block", f"'{blk['sel'][:40]}' is never closed with '}}'.", "Everything after it may be ignored.", "Add the missing '}'.")
    if not state["bb"]:
        for wpos, (ins, ind) in pending:
            add(wpos, "MEDIUM", "Width 100% plus padding/border overflows", "With the default content-box sizing, padding and border are added on top of width: 100%.", "The element is wider than its container and causes horizontal scrolling.", "Add box-sizing: border-box.", "box-sizing: border-box;", conf=0.8, status="Potential")
            edit(ins, "\n" + ind + "box-sizing: border-box;", "Added box-sizing: border-box to prevent overflow")
    return out, edits

def css_fix(src):
    src = src.replace("\r\n", "\n").replace("\r", "\n")
    _, edits = analyze_css(src); counts = {}
    for pos, _s, text, desc in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        src = src[:pos] + text + src[pos:]; counts[desc] = counts.get(desc, 0) + 1
    return src, [f"{d} ({k}x)" if k > 1 else d for d, k in counts.items()]
