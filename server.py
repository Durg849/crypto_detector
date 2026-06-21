from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import uvicorn
import uuid
import datetime
import json
import os
import re

app = FastAPI(title="Injecto API")

# FIX: Use absolute path for templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates."))

# ─── Simple file-based DB for API keys ───────────────────────────────────────
KEYS_FILE = "api_keys.json"

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            return json.load(f)
    return {}

def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)

# ─── Injection Detection ────────────────────────────────────────────────────
FIREWALL_WORDS = [
    "reveal password", "show api key", "system secret", "database password"
]

SUSPICIOUS_PATTERNS = [
    "ignore previous instructions", "reveal system prompt", "bypass safety",
    "developer mode", "act as system", "pretend you are", "disable restrictions",
    "jailbreak", "override rules", "ignore all instructions", "act as dan",
    "forget your training", "new persona", "disregard system",
    "you are now", "ignore your rules", "bypass all"
]

ATTACK_MAP = {
    "ignore previous instructions": "Instruction Override",
    "ignore all instructions": "Instruction Override",
    "reveal system prompt": "Data Exfiltration",
    "pretend you are": "Role Manipulation",
    "you are now": "Role Manipulation",
    "bypass safety": "Safety Bypass",
    "jailbreak": "Jailbreak Attack",
    "act as dan": "Jailbreak Attack",
    "developer mode": "Developer Mode Exploit",
}

def firewall_check(prompt: str) -> bool:
    return any(w in prompt.lower() for w in FIREWALL_WORDS)

def detect_injection(prompt: str):
    found = [p for p in SUSPICIOUS_PATTERNS if p in prompt.lower()]
    return len(found) > 0, found

def calculate_risk(patterns):
    if len(patterns) == 0: return 10
    elif len(patterns) == 1: return 40
    elif len(patterns) == 2: return 70
    else: return 90

def severity_level(risk):
    if risk < 30: return "LOW"
    elif risk < 70: return "MEDIUM"
    else: return "HIGH"

def get_attack_types(patterns):
    types = list({ATTACK_MAP.get(p, "Unknown Attack") for p in patterns})
    return types if types else ["Unknown Attack"]

def analyze_prompt(prompt: str) -> dict:
    timestamp = datetime.datetime.now().isoformat()
    if firewall_check(prompt):
        return {
            "timestamp": timestamp,
            "safe": False,
            "blocked_by": "firewall",
            "reason": "Prompt contains forbidden content",
            "risk_score": 100,
            "severity": "HIGH",
            "attack_types": ["Firewall Block"],
            "patterns": [],
        }
    detected, patterns = detect_injection(prompt)
    risk = calculate_risk(patterns)
    severity = severity_level(risk)
    attack_types = get_attack_types(patterns)
    return {
        "timestamp": timestamp,
        "safe": not detected,
        "blocked_by": "rule_engine" if detected else None,
        "reason": "Prompt injection detected" if detected else "Prompt is safe",
        "risk_score": risk,
        "severity": severity,
        "attack_types": attack_types,
        "patterns": patterns,
        "prompt_length": len(prompt.split()),
    }

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE = "server_logs.json"

def log_event(data: dict):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            try: logs = json.load(f)
            except: logs = []
    logs.append(data)
    with open(LOG_FILE, "w") as f:
        json.dump(logs[-1000:], f)

# ─── API Key auth ─────────────────────────────────────────────────────────────
def verify_api_key(request: Request):
    key = request.headers.get("x-api-key") or request.headers.get("authorization", "").replace("Bearer ", "")
    if not key:
        raise HTTPException(status_code=401, detail="API key required")
    keys = load_keys()
    if key not in keys:
        raise HTTPException(status_code=403, detail="Invalid API key")
    keys[key]["requests"] = keys[key].get("requests", 0) + 1
    keys[key]["last_used"] = datetime.datetime.now().isoformat()
    save_keys(keys)
    return keys[key]

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/pricing", response_class=HTMLResponse)
async def pricing(request: Request):
    return templates.TemplateResponse("pricing.html", {"request": request})

@app.get("/docs-page", response_class=HTMLResponse)
async def docs_page(request: Request):
    return templates.TemplateResponse("docs.html", {"request": request})

@app.post("/demo/detect")
async def demo_detect(request: Request):
    body = await request.json()
    prompt = body.get("prompt", "")
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")
    result = analyze_prompt(prompt)
    log_event({"source": "demo", **result})
    return result

@app.post("/api/detect")
async def api_detect(request: Request, account=Depends(verify_api_key)):
    body = await request.json()
    prompt = body.get("prompt", "")
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")
    result = analyze_prompt(prompt)
    log_event({"source": "api", "account": account.get("email"), **result})
    return result

@app.post("/admin/create-key")
async def create_key(request: Request):
    body = await request.json()
    email = body.get("email", "unknown")
    plan = body.get("plan", "starter")
    new_key = "inj_" + uuid.uuid4().hex[:24]
    keys = load_keys()
    keys[new_key] = {
        "email": email,
        "plan": plan,
        "created": datetime.datetime.now().isoformat(),
        "requests": 0,
        "active": True
    }
    save_keys(keys)
    return {"api_key": new_key, "email": email, "plan": plan}

@app.get("/api/stats")
async def stats(account=Depends(verify_api_key)):
    return {
        "email": account.get("email"),
        "plan": account.get("plan"),
        "total_requests": account.get("requests", 0),
        "last_used": account.get("last_used"),
    }

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
