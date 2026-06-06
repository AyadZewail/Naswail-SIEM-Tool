import requests
import base64
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List
import re
from nfstream import NFStreamer

class IAnomalyDetector(ABC):
    @abstractmethod
    def check(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Determines whether a packet is anomalous based on internal detection logic.

        Returns:
            A dictionary describing the anomaly if detected, otherwise None.
        """
        pass


class MLAnomalyDetector(IAnomalyDetector):
    def __init__(self, ids_url):
        self.ids_url = ids_url

    def check(self, packet: Any) -> Optional[Dict[str, Any]]:
        self.pcap = packet

        with open(self.pcap, "rb") as f:
            pcap_data = base64.b64encode(f.read()).decode('utf-8')

        payload = {
            "filename": self.pcap.split("\\")[-1],
            "content": pcap_data
        }

        response = requests.post(f"{self.ids_url}/detect/ml", json=payload)
        data = response.json()

        if "results" in data:
            return data["results"]

        return None


class DLAnomalyDetector(IAnomalyDetector):
    def __init__(self, ids_url):
        self.ids_url = ids_url

    def check(self, packet: Any) -> Optional[Dict[str, Any]]:
        self.pcap = packet

        with open(self.pcap, "rb") as f:
            pcap_data = base64.b64encode(f.read()).decode('utf-8')

        payload = {
            "filename": self.pcap.split("\\")[-1],
            "content": pcap_data
        }

        response = requests.post(f"{self.ids_url}/detect/dl", json=payload)
        data = response.json()

        if "results" in data:
            return data["results"]

        return None


class CloudAnomalyDetector(IAnomalyDetector):
    """
    Parent wrapper for ML + DL detectors.
    After collecting predictions, it returns **only the flows that are NOT normal**.
    """
    def __init__(self, ids_url):
        self.ids_url = ids_url

    def _filter_non_normal(self, combined: str) -> List[Dict[str, Any]]:
        results = []
        for raw in combined.splitlines():
            raw = raw.strip()
            if not raw:
                continue

            # --- NEW FORMAT: "Anomaly at flow idx 1948" ---------------------------
            idx_match = re.search(r'flow idx\s*(\d+)', raw, re.IGNORECASE)
            if idx_match:
                flow = int(idx_match.group(1))

                if "Anomaly" in raw:
                    results.append({"flow": flow, "label": "Anomaly"})
                # if "Normal" in raw → skip
                continue
            # ----------------------------------------------------------------------

            # OLD FORMAT BELOW (unchanged)
            m = re.search(r'Flow\s*(\d+)', raw, re.IGNORECASE)
            if not m:
                continue
            flow = int(m.group(1))

            if re.search(r'\bNormal\b', raw, re.IGNORECASE):
                continue

            candidate = raw.split(':')[-1].strip()

            label = re.sub(r'[^\w\s\-]', ' ', candidate)
            label = re.sub(r'\bModel\b', ' ', label, flags=re.IGNORECASE)
            label = re.sub(r'\s+', ' ', label).strip()

            if not label:
                after_flow = raw[m.end():].strip()
                label = re.sub(r'[^\w\s\-]', ' ', after_flow)
                label = re.sub(r'\bModel\b', ' ', label, flags=re.IGNORECASE)
                label = re.sub(r'\s+', ' ', label).strip()

            if label and not re.search(r'\bNormal\b', label, re.IGNORECASE):
                results.append({"flow": flow, "label": label})

        return results

    
    def check(self, packet: Any) -> Optional[Dict[str, Any]]:
        self.pcap = packet

        ml_detector = MLAnomalyDetector(self.ids_url)
        dl_detector = DLAnomalyDetector(self.ids_url)

        ml_results = ml_detector.check(self.pcap)
        dl_results = dl_detector.check(self.pcap)

        # print(dl_results + "\n" + ml_results)

        m = re.search(r'idx\s*(\d+)', dl_results or "")
        first_idx = int(m.group(1)) if m else None
        # print(first_idx)

        # Combine results
        combined = ml_results + "\n" + dl_results
        anomalies = self._filter_non_normal(combined)

        streamer = NFStreamer(
            source=self.pcap,
            statistical_analysis=True,
            splt_analysis=20,
            n_dissections=10
        )
        df = streamer.to_pandas()

        # print(df)

        enriched = []

        for item in anomalies:
            flow_idx = item["flow"] - first_idx
            # print(flow_idx)

            # Defensive: skip if df doesn't have that index
            if flow_idx not in df.index:
                item["error"] = "flow_not_found_in_dataframe"
                enriched.append(item)
                continue

            row = df.loc[flow_idx]

            item["src_ip"] = row.get("src_ip")
            item["src_port"] = row.get("src_port")
            item["dst_ip"] = row.get("dst_ip")
            item["dst_port"] = row.get("dst_port")

            # NFStreamer typically uses 'protocol' OR 'proto' OR 'protocol_name'
            item["protocol"] = (
                row.get("protocol") or 
                row.get("proto") or 
                row.get("protocol_name")
            )

            enriched.append(item)

        # print(enriched)

        seen_flows = set()
        distinct_enriched = []
        for entry in enriched:
            if entry['flow'] not in seen_flows:
                distinct_enriched.append(entry)
                seen_flows.add(entry['flow'])

        print(distinct_enriched)
        return distinct_enriched


# Usage example
# if __name__ == "__main__":
#     cloud = CloudAnomalyDetector("http://101.46.64.170:8080")
#     result = cloud.check("D:\\Work\\University\\GradProject\\Naswail-SIEM-Tool\\data\\packet_file1.pcap")
#     print(result)
