import requests
import json
import re
from core.interfaces import IAutopilotEngine

class KaggleLLMEngine(IAutopilotEngine):
    def __init__(self, ngrok_url):
        self.api_url = f"{ngrok_url}/generate"
        self.log = ""

    def decide(self, prompt: str) -> str:
        try:
            response = requests.post(self.api_url, json={"prompt": prompt}, timeout=300)
            raw_text = response.json().get("response", "")

            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if not match:
                self.log = "No valid decision found in response."
                return "", self.log

            parsed = json.loads(match.group(0))
            action = parsed.get("function") or list(parsed.values())[0]

            return action, self.log
        except Exception as e:
            self.log = "[AutopilotEngine] LLM decision failed: {str(e)}"
            return "", self.log