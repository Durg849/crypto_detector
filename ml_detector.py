def ml_detect(prompt):
    if "ignore instructions" in prompt.lower():
        return "⚠️ Prompt Injection Detected"
    else:
        return "✅ Safe Prompt"
