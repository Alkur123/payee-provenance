"""Transport adapter: run the same harness against an OpenAI-compatible API (PR55 Amendment 1).

The harnesses keep Ollama-format message lists; this converts them on the way out and returns an Ollama-style message,
so episode logic, tool schemas, system prompt and turn limits are unchanged. Model names prefixed `groq:` go to Groq.
"""
import json
import os
import time
import urllib.error
import urllib.request

PROVIDERS = {"groq": ("https://api.groq.com/openai/v1/chat/completions", "GROQ_API_KEY"),
             "openai": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY")}
GROQ_URL = PROVIDERS["groq"][0]

# Spending guard for paid providers: USD per 1M (input, output) tokens, deliberately at or above list price, and a hard
# budget. Usage is read from every reply; the run stops with an error once the running cost reaches the budget.
PRICE_PER_M = {"gpt-4.1-mini": (0.40, 1.60), "gpt-4.1-mini-2025-04-14": (0.40, 1.60), "gpt-4o-mini": (0.15, 0.60), "gpt-4.1": (2.00, 8.00), "gpt-4o": (2.50, 10.00)}
BUDGET_USD = float(os.environ.get("PAID_API_BUDGET_USD", "3.0"))
SPENT = {"usd": 0.0, "in": 0, "out": 0}


def _key(var="GROQ_API_KEY"):
    k = os.environ.get(var, "")
    if not k:
        env = os.path.join(os.path.dirname(__file__), "..", "..", "..", "backend", ".env")
        if os.path.exists(env):
            for line in open(env, encoding="utf-8"):
                if line.startswith(var + "="):
                    k = line.split("=", 1)[1].strip().strip('"')
    if not k:
        raise RuntimeError(var + " not set")
    return k


def to_openai(messages):
    """Ollama-format -> OpenAI-format. Tool results are paired, in order, with the preceding assistant's tool calls."""
    out, pending = [], []
    for m in messages:
        if m["role"] == "assistant":
            calls = []
            for i, c in enumerate(m.get("tool_calls") or []):
                args = c["function"].get("arguments") or {}
                calls.append({"id": c.get("id") or f"call_{len(out)}_{i}", "type": "function",
                              "function": {"name": c["function"]["name"],
                                           "arguments": args if isinstance(args, str) else json.dumps(args)}})
            msg = {"role": "assistant", "content": m.get("content") or ""}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
            pending = [c["id"] for c in calls]
        elif m["role"] == "tool":
            out.append({"role": "tool", "tool_call_id": pending.pop(0) if pending else "call_orphan",
                        "content": m.get("content", "")})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    return out


def chat_openai_compatible(model, messages, tools, retries=8):
    provider, name = model.split(":", 1)
    url, var = PROVIDERS[provider]
    body = {"model": name, "temperature": 0, "messages": to_openai(messages), "tools": tools}
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + _key(var), "User-Agent": "payee-provenance"})
        if provider == "openai" and SPENT["usd"] >= BUDGET_USD:
            raise RuntimeError(f"budget reached: ${SPENT['usd']:.2f} of ${BUDGET_USD:.2f}")
        try:
            d = json.load(urllib.request.urlopen(req, timeout=120))
            if provider == "openai":
                u = d.get("usage") or {}
                pin, pout = PRICE_PER_M.get(name, (10.0, 40.0))     # unknown model: assume expensive
                SPENT["in"] += u.get("prompt_tokens", 0)
                SPENT["out"] += u.get("completion_tokens", 0)
                SPENT["usd"] = (SPENT["in"] * pin + SPENT["out"] * pout) / 1e6
            m = d["choices"][0]["message"]
            return {"role": "assistant", "content": m.get("content") or "", "tool_calls": m.get("tool_calls") or []}
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503) and attempt < retries - 1:
                wait = float(e.headers.get("retry-after") or 0) or min(60, 5 * 2 ** attempt)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):   # PR55 Amendment 2: network drop / no reply
            if attempt < retries - 1:
                time.sleep(min(60, 5 * 2 ** attempt))
                continue
            raise
