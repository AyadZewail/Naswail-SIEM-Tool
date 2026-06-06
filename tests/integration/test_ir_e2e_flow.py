import pytest
from unittest.mock import MagicMock

from plugins.incident_response.ThreatIntelligence import ThreatIntelligence
from plugins.incident_response.IntelPreprocessor import SimpleIntelPreprocessor
from controllers.IncidentResponse_Controller import IncidentResponseController, ScraperWorker

# 1. Mock Searcher (Bypasses the internet, returns deterministic text)
class MockSearcher:
    async def search(self, query_data: dict) -> dict:
        return {"raw_data": "We highly recommend blocking the attacker's IP address to stop the DDoS."}

# 2. Stub Autopilot (Bypasses DeepSeek API, returns deterministic action)
class StubAutopilotEngine:
    def decide(self, prompt: str):
        # The prompt will contain the output from the Preprocessor.
        # We stub the decision to guarantee the pipeline proceeds.
        return "block_ip", "Decided to block based on threat intel."

@pytest.fixture(scope="module")
def real_preprocessor():
    """Load the heavy AI preprocessor once"""
    return SimpleIntelPreprocessor()

def test_full_ir_scrape_to_mitigate_e2e(real_preprocessor):
    # ==========================================================
    # ARRANGE
    # ==========================================================
    
    # A) Build the Threat Intel Pipeline (Real Aggregator + Real Preprocessor)
    searchers = [MockSearcher()]
    threat_intel = ThreatIntelligence(searchers=searchers, preprocessor=real_preprocessor)
    
    # B) Build the Controller Dependencies (Stub Autopilot + Mock Mitigation)
    stub_autopilot = StubAutopilotEngine()
    mock_mitigation = MagicMock()
    
    controller = IncidentResponseController(
        ui=MagicMock(),
        anomalies=[],
        protocol_extractor=MagicMock(),
        autopilot_engine=stub_autopilot,
        threat_intel=threat_intel,
        blacklist=[],
        blocked_ports=[],
        network_log=[],
        mitigation_engine=mock_mitigation,
        autopilot_log=MagicMock(),
        main_window=MagicMock()
    )
    
    # Our test target data
    test_ip = "10.0.0.99"
    test_port = 80
    
    # We create a callback to catch the signal from the ScraperWorker
    # This acts as the "glue" that the GUI normally provides.
    def on_worker_finished(output_string):
        # We pipe the scraper's output directly into the controller's mitigate function.
        controller.mitigate(prompt=output_string, ip=test_ip, port=test_port, scrapetime=0.5)

    # We instantiate the worker that the GUI would normally spawn
    worker = ScraperWorker(query={"query": "DDoS attack"}, threatIntel=threat_intel)
    
    # Connect the PyQt signal manually to our callback
    worker.signals.finished.connect(on_worker_finished)
    
    # ==========================================================
    # ACT
    # ==========================================================
    
    # Instead of clicking a button and letting the QThreadPool run this in the background,
    # we manually invoke `.run()` to execute it immediately on the main test thread.
    worker.run()
    
    # ==========================================================
    # ASSERT
    # ==========================================================
    
    # If the ENTIRE chain worked:
    # 1. Worker asked ThreatIntel for data
    # 2. ThreatIntel got raw text from MockSearcher
    # 3. ThreatIntel fed text to real SimpleIntelPreprocessor
    # 4. Preprocessor extracted the mitigation sentence
    # 5. Worker emitted the finished signal with that sentence
    # 6. Our callback caught it and called mitigate()
    # 7. mitigate() asked the StubAutopilot what to do
    # 8. Autopilot said "block_ip"
    # 9. mitigate() used getattr() to dynamically call block_ip on the Mock Mitigation Engine
    
    # If ALL of that worked perfectly, this assertion will pass:
    mock_mitigation.block_ip.assert_called_once_with(test_ip)
