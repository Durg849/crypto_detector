# saga_orchestrator.py

class SagaOrchestrator:

    def __init__(self):
        # you can later add DB/logger/config here
        pass

    # STEP 1: Validation Service
    def validate(self, prompt):
        # call your existing validation logic here
        clean_prompt = prompt.strip()
        return clean_prompt

    # STEP 2: Injection Detection Service
    def detect_injection(self, prompt):
        # replace this with your existing ML / rule-based function
        # example: return detect_prompt(prompt)
        result = {
            "is_attack": False,
            "confidence": 0.2
        }
        return result

    # STEP 3: Risk Scoring Service
    def risk_score(self, detection_result):
        # simple example logic
        if detection_result["is_attack"]:
            return 90
        return 20

    # STEP 4: Policy Engine (decision maker)
    def decide(self, score):
        if score >= 70:
            return "BLOCKED 🚫"
        else:
            return "ALLOWED ✅"

    # STEP 5: Logging Service (optional but useful)
    def log(self, prompt, score, decision):
        print("=== LOG ===")
        print("Prompt:", prompt)
        print("Score:", score)
        print("Decision:", decision)
        print("===========")

    # 🔥 MAIN SAGA FLOW
    def execute(self, prompt):

        try:
            # Step 1
            clean_prompt = self.validate(prompt)

            # Step 2
            detection = self.detect_injection(clean_prompt)

            # Step 3
            score = self.risk_score(detection)

            # Step 4
            decision = self.decide(score)

            # Step 5
            self.log(clean_prompt, score, decision)

            return {
                "prompt": clean_prompt,
                "score": score,
                "decision": decision
            }

        except Exception as e:
            # SAFE fallback (very important for security projects)
            return {
                "error": str(e),
                "decision": "BLOCKED (SAFE MODE) 🚨"
            }