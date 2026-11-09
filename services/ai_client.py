"""Single AI client used by BOTH the code reviewer and the code generator.
Supports OpenAI-compatible chat endpoints and Anthropic's Messages API (auto-detected from AI_API_URL)."""
import os, requests

KEYS = ("AI_API_KEY", "AI_MODEL", "AI_API_URL")

class AIError(Exception):
    """Safe-to-display error message (never contains the API key)."""

def missing(): return [k for k in KEYS if not (os.getenv(k) or "").strip()]
def configured(): return not missing()
def provider(): return "anthropic" if "anthropic.com" in (os.getenv("AI_API_URL") or "") else "openai-compatible"

def chat(prompt, max_tokens=4000, timeout=60):
    if missing(): raise AIError("Missing in .env: " + ", ".join(missing()))
    key, model, url = (os.environ[k].strip() for k in KEYS)
    msgs = [{"role": "user", "content": prompt}]
    if provider() == "anthropic":
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        body = {"model": model, "max_tokens": max_tokens, "messages": msgs}
    else:  # temperature/max_tokens omitted on purpose: some newer models reject them
        headers = {"Authorization": f"Bearer {key}"}
        body = {"model": model, "messages": msgs}
    try:
        r = requests.post(url, headers=headers, json=body, timeout=timeout)
    except requests.RequestException:
        raise AIError("Could not reach AI_API_URL. Check the URL and your internet connection.")
    if r.status_code >= 400:
        hint = {400: "Bad request (check AI_MODEL)", 401: "API key rejected", 403: "Access denied for this key",
                404: "AI_API_URL or AI_MODEL not found", 429: "Rate limit or quota exceeded"}.get(r.status_code, "Provider error")
        detail = ""
        try:
            e = r.json().get("error", "")
            detail = (e.get("message", "") if isinstance(e, dict) else str(e)).replace(key, "***")[:200]
        except Exception: pass
        raise AIError(f"{hint} (HTTP {r.status_code}). {detail}".strip())
    try:
        d = r.json()
        return d["content"][0]["text"] if provider() == "anthropic" else d["choices"][0]["message"]["content"]
    except Exception:
        raise AIError("Unexpected response format. Check that AI_API_URL is the chat-completions / messages endpoint.")
