import json, re
from services.ai_client import chat, configured, AIError
PROMPT = """Analyze only the supplied {lang} source code. Do not invent code that is not present. Do not report generic issues unless relevant.
Return STRICT JSON only: {{"summary": str, "findings": [{{"category": "Security|Bug|Quality|Performance|Maintainability", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "title": str, "line": int, "explanation": str, "impact": str, "recommendation": str, "suggested_fix": str, "confidence": 0-1}}]}}
Already found by static analysis (do not repeat): {known}
SOURCE (numbered):
{code}"""
CATS = {"Security", "Bug", "Quality", "Performance", "Maintainability"}
SEVS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

def ai_review(lang, src, known_titles):
    """Returns (summary, findings, status). Never raises."""
    if not configured(): return "", [], "AI analysis not configured. Static analysis completed."
    lines = src.splitlines()
    numbered = "\n".join(f"{i}: {l}" for i, l in enumerate(lines, 1))
    try:
        text = chat(PROMPT.format(lang=lang, known=sorted(set(known_titles)), code=numbered), max_tokens=4000)
        data = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        out = []
        for f in data.get("findings", [])[:30]:
            ln = f.get("line")
            if f.get("category") not in CATS or f.get("severity") not in SEVS or not isinstance(ln, int) or not 1 <= ln <= len(lines): continue
            conf = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
            out.append(dict(category=f["category"], severity=f["severity"], title=str(f.get("title", ""))[:200], line_number=ln,
                code=lines[ln - 1].strip()[:300], explanation=str(f.get("explanation", "")), impact=str(f.get("impact", "")),
                recommendation=str(f.get("recommendation", "")), suggested_fix=str(f.get("suggested_fix", "")),
                confidence=conf, status="Potential" if conf < 0.9 else "Confirmed", source="ai"))
        return str(data.get("summary", ""))[:500], out, "AI analysis completed."
    except AIError as e:
        return "", [], f"Static analysis completed. AI unavailable: {e}"
    except Exception as e:
        print("AI parse error:", repr(e))
        return "", [], "Static analysis completed. The AI reply could not be understood."
