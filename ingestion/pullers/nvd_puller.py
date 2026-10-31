import os
import time
import requests
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Generator, List, Dict, Optional

class NVDFetcher:
    def __init__(self):
        self.root = self._find_project_root()
        self.key_path = self.root / 'configs' / 'ak.env'
        self.api_key = self._get_api_key()
        
        if self.api_key:
            self.max_workers = 5
            self.api_delay = 0.8
        else:
            self.max_workers = 1
            self.api_delay = 6.5
        
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _find_project_root(self) -> Path:
            current = Path(__file__).resolve().parent
            
            for path in [current] + list(current.parents):
                has_main = (path / 'main.py').exists()
                has_configs = (path / 'configs').is_dir()
                
                if has_main and has_configs:
                    return path

            return Path(__file__).resolve().parent.parent.parent

    def _get_api_key(self) -> Optional[str]:
        if self.key_path.exists():
            load_dotenv(dotenv_path=self.key_path, override=True)
            apikey = os.getenv("NVD_API_KEY")
            return apikey.strip() if apikey and apikey.upper() != "NONE" else None
        return None

    def fetch_batch(self, session: requests.Session, params: Dict[str, Any], start_index: int) -> List[Dict[str, Any]]:
        local_params = {**params, 'startIndex': start_index}
        time.sleep(self.api_delay) 

        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = session.get(self.base_url, params=local_params, timeout=30)
                if response.status_code == 200:
                    return response.json().get('vulnerabilities', [])

                if response.status_code in {429, 500, 502, 503, 504}:
                    retry_after = float(response.headers.get('Retry-After', 5))
                    time.sleep((2 ** attempt) + retry_after)
                    continue
                
                response.raise_for_status()
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                if attempt == max_retries - 1: raise
                time.sleep(2 ** attempt)
        return []

    def stream_raw_data(self, mode: str = 'lastmod', previous_days: int = 7, chunk_limit: int = 2000, limit: Optional[int] = None) -> Generator[List[Dict[str, Any]], None, None]:
        headers = {'apiKey': self.api_key} if self.api_key else {}
        params: Dict[str, Any] = {'resultsPerPage': chunk_limit}
        
        if mode == 'lastmod':
            now = datetime.now(timezone.utc)
            start_date = (now - timedelta(days=previous_days)).strftime('%Y-%m-%dT%H:%M:%S.000')
            end_date = now.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['lastModStartDate'] = start_date
            params['lastModEndDate'] = end_date

        with requests.Session() as session:
            session.headers.update(headers)
            
            r = session.get(self.base_url, params={**params, 'resultsPerPage': 1}, timeout=15)
            r.raise_for_status()
            
            api_total = r.json().get('totalResults', 0)
            total = min(api_total, limit) if limit else api_total
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [
                    executor.submit(self.fetch_batch, session, params, i) 
                    for i in range(0, total, chunk_limit)
                ]
                for future in as_completed(futures):
                    batch = future.result()
                    if batch:
                        yield batch

if __name__ == "__main__":
    fetcher = NVDFetcher()
    print(f"Project Root: {fetcher.root}")
    print(f"Config Path:  {fetcher.key_path}")
    print(f"API Key Found: {'Yes' if fetcher.api_key else 'No (using public rate limits)'}")