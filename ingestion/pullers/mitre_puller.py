import requests
from typing import Dict, List, Any, Generator, Optional

class MITREFetcher:
    def __init__(self):
        self.matrix_urls = {
            "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
            "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
        }

    def fetch_raw_matrices(self) -> Generator[Dict[str, Any], None, None]:
        for name, url in self.matrix_urls.items():
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                yield response.json()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching MITRE matrix '{name}': {e}")
                continue