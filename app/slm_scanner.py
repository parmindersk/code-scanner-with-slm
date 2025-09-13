import os, re, json, glob, textwrap
import requests

ROOT = os.path.dirname(__file__)
NODE_MODULES = os.path.join(ROOT, "node_modules")
PKG_NAME = os.environ.get("DEMO_PKG", "kleurx")
PKG_DIR = os.path.join(NODE_MODULES, PKG_NAME)

# Heuristic patterns 
PATTERNS = {
    "env_access": r"\bprocess\.env\b",
    "http_egress": r"\bhttp\.(request|get)\b|\bhttps\.(request|get)\b|\bnet\.connect\b",
    "base64_decode": r"Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]\s*\)",
    "child_process": r"\bchild_process\b",
    "new_function": r"new\s+Function\s*\(",
    "eval": r"\beval\s*\("
}

def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def collect_pkg_signals():
    """Scan the target package for heuristic signals, return list of hits per file."""
    files = []
    signals = []

    if not os.path.isdir(PKG_DIR):
        return {"files": [], "signals": []}

    for ext in ("js", "mjs", "cjs", "json"):
        files.extend(glob.glob(os.path.join(PKG_DIR, f"**/*.{ext}"), recursive=True))

    for fp in files:
        txt = read_text(fp)
        if not txt:
            continue
        hits = []
        for name, pat in PATTERNS.items():
            if re.search(pat, txt):
                hits.append(name)
        if hits:
            signals.append({
                "file": os.path.relpath(fp, ROOT),
                "hits": sorted(set(hits)),
                "snippet": txt[:1200]  # keep prompt small
            })

    return {"files": files, "signals": signals}

def slm_review(snippet: str, model: str | None = None, base_url: str | None = None) -> dict:
    model = model or os.environ.get("SLM_MODEL", "llama3.2:3b")
    base = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
    url = f"{base}/api/chat"

    prompt = textwrap.dedent(f"""
    You are a security code reviewer for supply-chain risks.
    Analyze the dependency snippet BELOW and return ONLY strict JSON:

    {{
      "risk": "low|medium|high",
      "issues": ["short issue 1", "short issue 2"],
      "explanation": "2-4 sentences, one paragraph"
    }}

    Consider behaviors like:
    - environment variable access
    - network egress (HTTP/HTTPS/net) on import
    - use of obfuscation (base64) or dynamic code (eval/new Function)
    - child process usage

    Code:
    ---
    {snippet}
    ---
    """).strip()

    payload = {
        "model": model,
        "stream": False,
        "options": {"temperature": 0, "num_ctx": 4096},
        "messages": [{"role": "user", "content": prompt}],
        "format": "json"
    }

    try:
        r = requests.post(url, json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()
        text = (data.get("message", {}) or {}).get("content", "").strip()
        if text.startswith("```"):
            text = text.strip("`")
            if "\n" in text:
                text = text.split("\n", 1)[1]
        return json.loads(text)
    except requests.HTTPError as e:
        return {"risk": "unknown", "issues": [], "explanation": f"Ollama HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"risk": "unknown", "issues": [], "explanation": f"SLM call failed: {type(e).__name__}: {e}"}

def summarize(signals: list[dict]) -> list[str]:
    """Combine weak signals into concise issues."""
    all_hits = {h for s in signals for h in s["hits"]}
    issues = []
    if "env_access" in all_hits and ("http_egress" in all_hits):
        issues.append("Environment access combined with network egress (possible data exfiltration).")
    if "base64_decode" in all_hits and ("new_function" in all_hits or "eval" in all_hits):
        issues.append("Obfuscated payload decoded and executed dynamically.")
    if "child_process" in all_hits and ("http_egress" in all_hits or "env_access" in all_hits):
        issues.append("Child process usage alongside sensitive API access.")
    if not issues and all_hits:
        issues.append("Suspicious runtime side effects detected in dependency.")
    return issues

def main():
    out = collect_pkg_signals()
    ranked = sorted(out["signals"], key=lambda s: -len(s["hits"]))
    if ranked:
        slm = slm_review(ranked[0]["snippet"])
        summary = summarize(out["signals"])
    else:
        slm = {"risk": "none", "issues": [], "explanation": "No suspicious signals found."}
        summary = []

    report = {
        "package": PKG_NAME,
        "signals_found": out["signals"],
        "behavior_issues": summary,
        "slm_result": slm
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
