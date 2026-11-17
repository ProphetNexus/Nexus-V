import os
import time
import random
import threading
import orjson
import requests
from requests.adapters import HTTPAdapter
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import Any, Generator, List, Dict, Optional

class NVDFetcher:
    def __init__(self):
        self.root = self._find_project_root()
        self.key_path = self.root / 'configs' / 'ak.env'
        self.api_key = self._get_api_key()
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0
        
        if self.api_key:
            self.max_workers = 5
            # NVD allows 50 requests per 30 seconds (1 req / 0.6s) with an API key
            self.min_interval = 0.65
        else:
            self.max_workers = 1
            # NVD allows 5 requests per 30 seconds (1 req / 6.0s) without an API key
            self.min_interval = 6.2
        
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _find_project_root(self) -> Path:
        current = Path(__file__).resolve().parent
        for path in [current] + list(current.parents):
            if (path / 'main.py').exists() and (path / 'configs').is_dir():
                return path
        return Path(__file__).resolve().parent.parent.parent

    def _get_api_key(self) -> Optional[str]:
        if self.key_path.exists():
            load_dotenv(dotenv_path=self.key_path, override=True)
            apikey = os.getenv("NVD_API_KEY")
            return apikey.strip() if apikey and apikey.upper() != "NONE" else None
        return None

    def _wait_for_rate_limit(self):
        """Thread-safe token pacer ensuring global request rate never exceeds NVD limits."""
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            wait_time = self.min_interval - elapsed
            if wait_time > 0:
                time.sleep(wait_time + random.uniform(0.02, 0.08))
            self._last_request_time = time.monotonic()

    def fetch_batch(self, session: requests.Session, params: Dict[str, Any], start_index: int) -> List[Dict[str, Any]]:
        local_params = {**params, 'startIndex': start_index}

        max_retries = 5
        for attempt in range(max_retries):
            try:
                self._wait_for_rate_limit()

                response = session.get(self.base_url, params=local_params, timeout=30)
                if response.status_code == 200:
                    return orjson.loads(response.content).get('vulnerabilities', [])

                if response.status_code in {429, 500, 502, 503, 504}:
                    retry_after = float(response.headers.get('Retry-After', 6))
                    backoff = (2 ** attempt) + retry_after + random.uniform(0.1, 0.5)
                    time.sleep(backoff)
                    continue
                
                response.raise_for_status()
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                if attempt == max_retries - 1:
                    raise
                time.sleep((2 ** attempt) + random.uniform(0.1, 0.5))

        raise RuntimeError(f"Failed to fetch NVD batch at startIndex={start_index} after {max_retries} retries.")

    def stream_raw_data(self, mode: str = 'lastmod', previous_days: int = 7) -> Generator[List[Dict[str, Any]], None, None]:
            CHUNK_LIMIT = 2000  # Hardcoded page size

            if mode == 'lastmod' and previous_days > 120:
                raise ValueError("NVD API 2.0 restricts lastMod date ranges to a maximum of 120 days.")

            params: Dict[str, Any] = {'resultsPerPage': CHUNK_LIMIT, 'startIndex': 0}
            
            if mode == 'lastmod':
                now = datetime.now(timezone.utc)
                start_date = (now - timedelta(days=previous_days)).strftime('%Y-%m-%dT%H:%M:%S.000')
                end_date = now.strftime('%Y-%m-%dT%H:%M:%S.000')
                params['lastModStartDate'] = start_date
                params['lastModEndDate'] = end_date

            with requests.Session() as session:
                adapter = HTTPAdapter(pool_connections=self.max_workers, pool_maxsize=self.max_workers)
                session.mount("https://", adapter)
                session.headers.update({
                    'Accept-Encoding': 'gzip, deflate',
                    **({'apiKey': self.api_key} if self.api_key else {})
                })
                
                # Fetch first batch immediately to get totalResults AND the first chunk
                self._wait_for_rate_limit()
                r = session.get(self.base_url, params=params, timeout=30)
                r.raise_for_status()
                
                payload = orjson.loads(r.content)
                total = payload.get('totalResults', 0)
                
                first_batch = payload.get('vulnerabilities', [])
                if first_batch:
                    yield first_batch
                
                if total <= CHUNK_LIMIT:
                    return

                offsets = range(CHUNK_LIMIT, total, CHUNK_LIMIT)
                
                # Bounded sliding window with ThreadPoolExecutor for backpressure control
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    offset_iter = iter(offsets)
                    in_flight = set()
                    
                    # Initial seed window
                    for _ in range(min(self.max_workers * 2, total // CHUNK_LIMIT + 1)):
                        try:
                            off = next(offset_iter)
                            in_flight.add(executor.submit(self.fetch_batch, session, params, off))
                        except StopIteration:
                            break

                    while in_flight:
                        done, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)
                        for future in done:
                            batch = future.result()
                            try:
                                off = next(offset_iter)
                                in_flight.add(executor.submit(self.fetch_batch, session, params, off))
                            except StopIteration:
                                pass
                            
                            if batch:
                                yield batch