import pytest

from plugins.incident_response.ThreatIntelligence import ThreatIntelligence
from plugins.incident_response.IntelPreprocessor import SimpleIntelPreprocessor

class MockSearcher:
    def __init__(self, raw_data_return, should_fail=False):
        self.raw_data_return = raw_data_return
        self.should_fail = should_fail
        
    async def search(self, query_data: dict) -> dict:
        if self.should_fail:
            raise Exception("Simulated searcher failure")
        return {"raw_data": self.raw_data_return}

@pytest.fixture(scope="module")
def real_preprocessor():
    """
    Load the real preprocessor once per module to save time.
    """
    return SimpleIntelPreprocessor()

@pytest.mark.asyncio
async def test_threat_intelligence_pipeline_success(real_preprocessor):
    # Arrange: Use two successful searchers
    searcher1 = MockSearcher("This article explains how to block traffic using a firewall. ")
    searcher2 = MockSearcher("Another article says rate limiting is an effective mitigation strategy. ")
    searchers = [searcher1, searcher2]
    
    aggregator = ThreatIntelligence(searchers=searchers, preprocessor=real_preprocessor)
    
    # Act
    query = {"query": "DDoS attack"}
    result = await aggregator.gather(query)
    
    # Assert
    assert isinstance(result, dict)
    assert "mitigation" in result
    assert "score" in result
    assert isinstance(result["mitigation"], str)
    assert isinstance(result["score"], (float, int))
    assert result["score"] >= 0.0

@pytest.mark.asyncio
async def test_threat_intelligence_pipeline_partial_failure(real_preprocessor):
    # Arrange: Mix successful and failing searchers
    searcher1 = MockSearcher("Valid data about rate limiting. ")
    searcher2 = MockSearcher("", should_fail=True)  # This one fails
    searcher3 = MockSearcher("More valid data about restricting ips. ")
    searchers = [searcher1, searcher2, searcher3]
    
    aggregator = ThreatIntelligence(searchers=searchers, preprocessor=real_preprocessor)
    
    # Act
    query = {"query": "DDoS attack"}
    result = await aggregator.gather(query)
    
    # Assert
    assert isinstance(result, dict)
    assert "mitigation" in result
    assert isinstance(result["mitigation"], str)

@pytest.mark.asyncio
async def test_threat_intelligence_pipeline_all_failures(real_preprocessor):
    # Arrange: All searchers fail
    searcher1 = MockSearcher("", should_fail=True)
    searcher2 = MockSearcher("", should_fail=True)
    searchers = [searcher1, searcher2]
    
    aggregator = ThreatIntelligence(searchers=searchers, preprocessor=real_preprocessor)
    
    # Act
    query = {"query": "DDoS attack"}
    result = await aggregator.gather(query)
    
    # Assert
    assert isinstance(result, dict)
    # Based on SimpleIntelPreprocessor logic, an empty string input should result in this:
    assert result["mitigation"] == "No sentences were retrieved"
