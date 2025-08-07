from abc import ABC, abstractmethod
from typing import Dict

class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        """
        Perform a source-specific search using the provided query.

        Args:
            query (Dict): Structured data with relevant search parameters.

        Returns:
            Dict: Raw result or data extracted from the source.
        """
        pass

class IIntelPreprocessor(ABC):
    @abstractmethod
    def preprocess(self, raw_data: Dict) -> Dict:
        """
        Processes and normalizes raw search data.

        Args:
            raw_data (Dict): Combined results from all searchers.

        Returns:
            Dict: Cleaned, structured threat intelligence.
        """
        pass
