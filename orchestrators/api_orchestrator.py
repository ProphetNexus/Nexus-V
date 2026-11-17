import sys
import time
from modules.logger import log_manager
from ingestion.database.db_pool import DatabasePool
from ingestion.database.db_filler import Upsert
from ingestion.pullers.nvd_puller import NVDFetcher
from ingestion.processors.nvd_processor import NVDProcessor
from ingestion.pullers.mitre_puller import MITREFetcher
from ingestion.processors.mitre_processor import MITREProcessor

class APIManager:
    def __init__(self):
        self.logger = log_manager()
        try:
            self.db_pool = DatabasePool()
            self.nvd_fetcher = NVDFetcher()
            self.nvd_processor = NVDProcessor()
            
            self.mitre_fetcher = MITREFetcher()
            self.mitre_processor = MITREProcessor()
            
            self.filler = Upsert(self.db_pool)
        except Exception as e:
            self.logger.log_critical(f"APIManager failed to initialize infrastructure: {e}")
            sys.exit(1)

    def run_nvd_sync(self, mode='lastmod', days=None):
        start_time = time.time()
        days = days if days is not None else 7
        self.logger.log_info(f"NVD Sync Started | Mode: {mode.upper()} | Days: {days}")

        try:
            for raw_batch in self.nvd_fetcher.stream_raw_data(
                mode=mode, 
                previous_days=days
            ):
                processed_batch = self.nvd_processor.process_batch(raw_batch)
                del raw_batch  # Free raw JSON memory immediately before DB insert

                self.filler.process_and_save(processed_batch)
                del processed_batch  # Free processed tuples memory

            duration = round((time.time() - start_time) / 60, 2)
            self.logger.log_info(f"NVD Sync Completed Successfully in {duration} minutes.")

        except ValueError as ve:
            self.logger.log_error(f"Configuration Error: {ve}")
            sys.exit(1)
        except Exception as e:
            self.logger.log_error(f"NVD Sync Halted due to unrecoverable error: {e}")
            if any(x in str(e) for x in ["Connection", "Database", "pool"]):
                self.logger.log_critical(f"Infrastructure failure: {e}")
            sys.exit(1)

    def run_mitre_sync(self):
        self.logger.log_info("Starting MITRE ATT&CK Framework Full Refresh...")
        try:
            for raw_matrix in self.mitre_fetcher.fetch_raw_matrices():
                processed_batch = self.mitre_processor.process_matrix(raw_matrix)
                del raw_matrix
                
                self.filler.save_mitre_framework(processed_batch)
                del processed_batch
            
            self.logger.log_info("MITRE Sync Completed Successfully.")
        except Exception as e:
            self.logger.log_error(f"MITRE Sync Failed: {e}")

if __name__ == "__main__":
    manager = APIManager()
    manager.run_mitre_sync()
    manager.run_nvd_sync(mode='lastmod', days=120)