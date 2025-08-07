import requests
import json
import re
from core.interfaces import IAutopilotEngine

class KaggleLLMEngine(IAutopilotEngine):
    def __init__(self, ngrok_url, logger):
        self.api_url = f"{ngrok_url}/generate"
        self.logger = logger

    def decide(self, prompt: str) -> str:
        try:
            response = requests.post(self.api_url, json={"prompt": prompt}, timeout=300)
            raw_text = response.json().get("response", "")

            # Extract JSON block from the response
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if not match:
                self.logger.log_step("No valid decision found in response.")
                return ""

            parsed = json.loads(match.group(0))
            action = parsed.get("function") or list(parsed.values())[0]

            return action
        except Exception as e:
            self.logger.log_step(f"[AutopilotEngine] LLM decision failed: {str(e)}")
            return ""
