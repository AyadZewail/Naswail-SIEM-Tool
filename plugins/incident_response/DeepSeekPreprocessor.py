import requests
from abc import ABC, abstractmethod
from typing import Dict

class IIntelPreprocessor(ABC):
    @abstractmethod
    def preprocess(self, raw_data: str) -> Dict:
        pass


class LLMIntelPreprocessor(IIntelPreprocessor):
    def __init__(self, endpoint, api_token: str, model_name: str = "deepseek-v3.1"):
        """
        Args:
            api_token (str): Huawei Cloud ModelArts MaaS API token.
            model_name (str): "deepseek-v3.1" or "qwen3-32b"
        """
        self.api_token = api_token
        self.model_name = model_name
        self.endpoint = endpoint

    def _build_prompt(self, intel_text: str) -> str:
        """
        Creates a strong, structured prompt for extracting a mitigation instruction.
        """
        return f"""
            You are a cybersecurity threat-analysis engine. You will be given a block of raw intelligence text extracted from multiple sources.

            Your task:
            1. Fully analyze the text.
            2. Identify what mitigation action is most actionable, effective, and technically correct.
            3. Return **one single sentence** that clearly instructs an analyst or automated system what to do next.
            4. Evaluate your own certainty and assign a confidence score between 0 and 1.

            Rules:
            - Do NOT return multiple sentences.
            - The mitigation must be a direct action (e.g., "Rate-limit inbound SYN packets to X per second").
            - Avoid generic advice unless no specific mitigation exists.
            - Do NOT include explanations.
            - Do NOT include quotes from the text.
            - Your output must follow the strict JSON format below.

            Raw intelligence:
            {intel_text}

            Return ONLY the following JSON:
            {{
            "mitigation": "<single actionable sentence>",
            "score": <confidence_score>
            }}
        """

    def preprocess(self, raw_data: str) -> Dict:
        """
        Args:
            raw_data (Dict): expects {"raw_data": "<long text>"} from searchers
        
        Returns:
            Dict: {"mitigation": str, "score": float}
        """
        if not raw_data:
            return {"mitigation": "", "score": 0.0}

        prompt = self._build_prompt(raw_data)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}"  # Correct header for MaaS
        }

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        response = requests.post(self.endpoint, headers=headers, json=payload)

        # If the key is invalid you will get 401 here
        response.raise_for_status()

        data = response.json()

        # Expected LLM output is a JSON object encoded in text
        output_text = data["choices"][0]["message"]["content"]

        # Safely parse the dict returned by the LLM
        try:
            parsed = eval(output_text)  # safe since we expect strict JSON-like structure
        except Exception:
            parsed = {"mitigation": "", "score": 0.0}

        # Final normalized output
        return {
            "mitigation": parsed.get("mitigation", ""),
            "score": float(parsed.get("score", 0.0))
        }
