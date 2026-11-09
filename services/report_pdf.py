"""Professional PDF review report (reportlab)."""
import io, textwrap
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import BaseDocTemplate, Frame, HRFlowable, KeepTogether, PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle
from analyzers import label
from fixer import auto_fix

INK, MUTED, BRAND, LINE, SOFT = HexColor("#1b1a3a"), HexColor("#6b6b8a"), HexColor("#6a4cf0"), HexColor("#dcd9fb"), HexColor("#f5f4ff")
SEV = {"CRITICAL": "#c62828", "HIGH": "#ef6c00", "MEDIUM": "#b8860b", "LOW": "#1565c0", "INFO": "#607d8b"}
ORDER = list(SEV)
W = A4[0] - 30 * mm
L1 = lambda s: str("" if s is None else s).encode("latin-1", "replace").decode("latin-1")   # built-in fonts are Latin-1 only
tone = lambda n: "#2e7d32" if n >= 75 else "#b8860b" if n >= 60 else "#c62828"

def wrap(s, width=92):
    out = []
    for ln in L1(s).expandtabs(4).splitlines() or [""]:
        out += textwrap.wrap(ln, width, drop_whitespace=False, replace_whitespace=False, subsequent_indent="      ") or [""]
    return "\n".join(out)

def listing(src, bad, cap=400):
    lines, rows = L1(src).expandtabs(4).splitlines(), []
    for i, ln in enumerate(lines[:cap], 1):
        w = textwrap.wrap(ln, 86, drop_whitespace=False, replace_whitespace=False) or [""]
        rows.append(f"{'!' if i in bad else ' '}{i:>4} | {w[0]}"); rows += [f"{'':>6}| {x}" for x in w[1:]]
    if len(lines) > cap: rows.append(f"... {len(lines) - cap} more lines not shown")
    return "\n".join(rows)

def _page(c, doc):
    w, h = A4; c.saveState()
    c.setFillColor(BRAND); c.rect(0, h - 14 * mm, w, 14 * mm, stroke=0, fill=1)
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 12); c.drawString(15 * mm, h - 9 * mm, "CodeScan")
    c.setFont("Helvetica", 8.5); c.drawRightString(w - 15 * mm, h - 9 * mm, "AI Code Reviewer & Bug Detection System")
    c.setFillColor(MUTED); c.setFont("Helvetica", 8)
    c.drawString(15 * mm, 9 * mm, f"Review #{doc.rid}  |  generated {doc.gen}"); c.drawRightString(w - 15 * mm, 9 * mm, f"Page {doc.page}"); c.restoreState()

def build_pdf(d, user=""):
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13, textColor=INK)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10.5, textColor=MUTED)
    hd = ParagraphStyle("hd", parent=small, textColor=colors.white, fontName="Helvetica-Bold")
    h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=13, textColor=BRAND, spaceBefore=14, spaceAfter=3)
    code = ParagraphStyle("c", parent=ss["Code"], fontSize=7.5, leading=9.5, backColor=SOFT, borderPadding=4, textColor=INK)
    ctr, ctrs = ParagraphStyle("ct", parent=body, alignment=1, leading=24), ParagraphStyle("cts", parent=small, alignment=1)
    P = lambda t, st=body: Paragraph(escape(L1(t)).replace("\n", "<br/>"), st)
    H = lambda t: [Paragraph(t, h2), HRFlowable(width="100%", color=LINE, thickness=.7, spaceAfter=6)]
    fs, lang, src = d["findings"], d["language"], d["source_code"].replace("\r\n", "\n")
    created = datetime.fromisoformat(d["created_at"]).strftime("%d %b %Y, %H:%M UTC")
    s = [Paragraph("Code Review Report", ParagraphStyle("t", parent=body, fontName="Helvetica-Bold", fontSize=24, leading=28)),
         Paragraph(f"Review #{d['id']} &nbsp;|&nbsp; {escape(lang.upper())}", ParagraphStyle("st", parent=body, fontSize=11, textColor=MUTED)), Spacer(1, 10)]
    info = [("Review ID", f"#{d['id']}", "Prepared for", user or "-"), ("Language", lang.upper(), "Date", created), ("Lines of code", str(len(src.splitlines())), "Issues found", str(d["issue_count"]))]
    s += [Table([[P(a, small), P(b), P(c, small), P(e)] for a, b, c, e in info], colWidths=[W * .17, W * .33, W * .17, W * .33],
                style=TableStyle([("BOX", (0, 0), (-1, -1), .7, LINE), ("INNERGRID", (0, 0), (-1, -1), .4, LINE), ("BACKGROUND", (0, 0), (0, -1), SOFT), ("BACKGROUND", (2, 0), (2, -1), SOFT), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")])), Spacer(1, 12)]
    sc = [("Overall", d["overall_score"], 30), ("Security", d["security_score"], 20), ("Quality", d["quality_score"], 20), ("Maintainability", d["maintainability_score"], 20), ("Reliability", d["reliability_score"], 20)]
    cells = [[Paragraph(f'<font size="{sz}" color="{tone(n)}"><b>{n}</b></font><font size="9" color="#6b6b8a">/100</font>', ParagraphStyle(f"ct{sz}", parent=ctr, leading=sz + 10)), Paragraph(f"<b>{nm}</b>", ctrs), Paragraph(label(n), ctrs)] for nm, n, sz in sc]
    s.append(Table([cells], colWidths=[W * .28] + [W * .18] * 4, style=TableStyle([("BOX", (0, 0), (-1, -1), .7, LINE), ("INNERGRID", (0, 0), (-1, -1), .4, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), SOFT)]
                                                                       + [("LINEABOVE", (i, 0), (i, 0), 3, HexColor(tone(n))) for i, (_, n, _) in enumerate(sc)])))
    s += H("Summary") + [P(d["summary"]), P("Analysis: " + (d["ai_status"] or "-"), small)]
    if fs:
        counts = {k: sum(1 for f in fs if f["severity"] == k) for k in ORDER}; mx, bw = max(counts.values()), W - 130
        dr = Drawing(W, 14 * len(ORDER) + 4)
        for i, k in enumerate(ORDER):
            y = dr.height - 14 * (i + 1)
            dr.add(String(0, y + 2, k.title(), fontName="Helvetica", fontSize=8.5, fillColor=INK))
            dr.add(Rect(70, y, bw * counts[k] / mx, 9, fillColor=HexColor(SEV[k]), strokeColor=None))
            dr.add(String(76 + bw * counts[k] / mx, y + 2, str(counts[k]), fontName="Helvetica-Bold", fontSize=8.5, fillColor=INK))
        s += H("Severity breakdown") + [dr]
        rows = [[P(x, hd) for x in ("#", "Severity", "Category", "Line", "Issue")]]
        for i, f in enumerate(fs, 1):
            rows.append([P(str(i), small), Paragraph(f'<font color="{SEV.get(f["severity"], "#607d8b")}"><b>{escape(f["severity"])}</b></font>', small), P(f["category"], small), P(str(f["line_number"]), small), P(f["title"], small)])
        s += H("Findings overview") + [Table(rows, colWidths=[W * .06, W * .14, W * .16, W * .08, W * .56], repeatRows=1, style=TableStyle([("BACKGROUND", (0, 0), (-1, 0), BRAND), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]), ("BOX", (0, 0), (-1, -1), .5, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))]
        seen, acts = set(), []
        for f in fs:
            if f["title"] not in seen and f["recommendation"]: seen.add(f["title"]); acts.append(f"{f['title']} (line {f['line_number']}): {f['recommendation']}")
        s += H("Priority actions") + [P(f"{i}. {a}") for i, a in enumerate(acts[:5], 1)] + H("Detailed findings")
        for i, f in enumerate(fs, 1):
            col = SEV.get(f["severity"], "#607d8b")
            blk = [Paragraph(f'<font backColor="{col}" color="white"><b>&nbsp;{escape(f["severity"])}&nbsp;</b></font>&nbsp; <b>{i}. {escape(L1(f["title"]))}</b>', body),
                   Paragraph(f'{escape(L1(f["category"]))} &nbsp;|&nbsp; Line {f["line_number"]} &nbsp;|&nbsp; {escape(L1(f["status"]))} &nbsp;|&nbsp; Confidence {round((f["confidence"] or 0) * 100)}% &nbsp;|&nbsp; Source: {escape(L1(f["source"]))}', small), Spacer(1, 3)]
            if f["code"]: blk.append(Preformatted(wrap(f["code"]), code))
            rest = [Spacer(1, 3)] + [Paragraph(f"<b>{t}:</b> {escape(L1(f[k]))}", body) for t, k in (("Why it is a problem", "explanation"), ("Impact", "impact"), ("Recommendation", "recommendation"))]
            if f["suggested_fix"]: rest += [Spacer(1, 3), Paragraph("<b>Suggested fix:</b>", body), Preformatted(wrap(f["suggested_fix"])[:1500], code)]
            s += [KeepTogether(blk), *rest, Spacer(1, 4), HRFlowable(width="100%", color=LINE, thickness=.4, spaceAfter=8)]
    else: s += H("Findings") + [P("No issues were detected by the enabled analyzers.")]
    bad = {f["line_number"] for f in fs if f["line_number"]}
    s += H("Reviewed source code") + [P("Lines marked with ! have findings.", small), Preformatted(listing(src, bad), code)] + H("Suggested code")
    fixed, changes = auto_fix(lang, src)
    if fixed.strip() == src.strip(): s.append(P("No automatic corrections were available. Follow the recommendations above."))
    else: s += [P("Applied automatically: " + "; ".join(changes), small), Preformatted(listing(fixed, set()), code)]
    s += [Spacer(1, 12), P("Produced by automated analysis (static rules with optional AI review). Findings marked Potential or Suggestion should be confirmed manually before changing code.", small)]
    buf = io.BytesIO(); doc = BaseDocTemplate(buf, pagesize=A4, title=f"CodeScan report #{d['id']}", author="CodeScan")
    doc.rid, doc.gen = d["id"], datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    doc.addPageTemplates([PageTemplate("p", frames=[Frame(15 * mm, 16 * mm, W, A4[1] - 34 * mm, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=_page)])
    doc.build(s); return buf.getvalue()
