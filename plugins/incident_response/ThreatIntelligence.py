from core.interfaces import IThreatIntelAggregator
from plugins.incident_response.interfaces import ISourceSearcher, IIntelPreprocessor

class ThreatIntelligence(IThreatIntelAggregator):
    def __init__(self, searchers: list[ISourceSearcher], preprocessor: IIntelPreprocessor):
        self.searchers = searchers
        self.preprocessor = preprocessor

    async def gather(self, query_data: dict) -> dict:
        all_results = []

        for searcher in self.searchers:
            try:
                results = await searcher.search(query_data)
                if results:
                    all_results.extend(results)
            except Exception as e:
                print(f"[Aggregator] Searcher {searcher.__class__.__name__} failed: {e}")

        combined_data = {'data': all_results}
        processed = self.preprocessor.preprocess(combined_data)
        return processed
