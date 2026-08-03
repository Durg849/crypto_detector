import requests

PIPELOCK_URL = "http://127.0.0.1:9090/api/v1/scan"
TOKEN = "injecto-secret-token"

def scan_prompt(prompt: str):
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "kind": "prompt_injection",
        "input": {
            "content": prompt
        }
    }

    try:
        r = requests.post(
            PIPELOCK_URL,
            headers=headers,
            json=payload,
            timeout=5
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {
            "status": "error",
            "decision": "deny",
            "error": str(e)
        }
