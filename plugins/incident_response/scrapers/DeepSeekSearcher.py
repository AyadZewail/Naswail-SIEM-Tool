import requests
from abc import ABC, abstractmethod
from typing import Dict


class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        pass


class DeepSeekSourceSearcher(ISourceSearcher):
    """
    Concrete implementation of ISourceSearcher for Huawei Cloud DeepSeek API.
    """

    def __init__(self, url, api_token, model_name):
        self.url = url
        self.api_token = api_token
        self.model_name = model_name

    def _build_prompt(self, attack_query: str) -> str:
        """
        Creates a well-engineered, reusable prompt template for mitigation retrieval.
        """

        return f"""
            You are a distributed cybersecurity intelligence agent.

            Your task: Perform a comprehensive search across:
            - academic sources
            - technical documentation
            - offensive attack playbooks
            - MITRE ATT&CK / D3FEND mappings
            - cloud and network security best practices
            - enterprise hardening guidelines
            - historical incident case studies

            Objective:
            Identify **complete, structured, multi-layer mitigation strategies** for the following attack:
            "{attack_query}"

            Requirements:
            1. Provide detailed and actionable steps.
            2. Cover network, application, host, identity, and cloud layers.
            3. Include zero-day-resilient strategies.
            4. Include monitoring/detection recommendations.
            5. Include immediate response actions and long-term hardening.
            6. Reference related MITRE ATT&CK techniques.
            7. Return everything in clear, structured text.
        """

    def search(self, query: Dict) -> Dict:
        """
        Executes the LLM search and returns {"source": "DeepSeek", "raw_data": "..."}.
        """

        attack_query = query.get("query", "")
        prompt = self._build_prompt(attack_query)

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        headers = {
            "Content-Type": "application/json",
            "X-Auth-Token": self.api_token
            # "Authorization": f"Bearer {self.api_token}"
        }

        response = requests.post(self.url, json=payload, headers=headers)
        print("Status:", response.status_code)
        print("Response:", response.text)
        print("Headers Sent:", headers)

        response.raise_for_status()

        data = response.json()

        # Extract model text safely
        raw_output = data.get("choices", [{}])[0].get("message", {}).get("content", "")

        return {
            "source": "DeepSeek",
            "raw_data": raw_output
        }


if __name__ == "__main__":

    # Instantiate searcher
    searcher = DeepSeekSourceSearcher("https://api-ap-southeast-1.modelarts-maas.com/v1/chat/completions", 
                                    "fce64bd1-948b-4b4d-b998-729fc4c12db8_8947A6A7229BA554F81256D428EB618303FE2E35A63A8C29FF0F98F7EAAB85CA",
                                    "deepseek-v3.1")

    # Example query structure
    test_query = {"query": "DDoS mitigation"}

    # Execute search
    result = searcher.search(test_query)

    # Print result for verification
    print("Search Result:")
    print(result)
