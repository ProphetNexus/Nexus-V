import yaml
import pandas as pd
from pathlib import Path

class DBReader:
    def __init__(self, db_pool):
        self.db_pool = db_pool
        self.root = self.db_pool._find_project_root()
        
        query_config = self.root / 'configs' / 'queries.conf'
        if not query_config.exists():
            raise FileNotFoundError(f"Configuration file not found: {query_config}")
            
        try:
            with open(query_config, 'r') as f:
                self.premade_queries = yaml.safe_load(f).get('queries', {})
        except Exception as e:
            raise RuntimeError(f"Critical configuration error in DBReader: {e}") from e

    def run_query(self, query_type=None, start_date=None, end_date=None, search_term=None):
        if query_type not in self.premade_queries:
            raise KeyError(f"Query type '{query_type}' is not defined.")

        conn = self.db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
            
        try:
            if query_type == "search_by_cpe_keyword":
                params = (f"%{search_term}%", start_date, end_date)
            else:
                params = (start_date, end_date)
                
            cursor.execute(self.premade_queries[query_type], params)
            return pd.DataFrame(cursor.fetchall())
        except Exception as e:
            raise RuntimeError(f"Execution of SQL query '{query_type}' failed") from e
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    try:
        from ingestion.database.db_pool import DatabasePool
        pool = DatabasePool()
        reader = DBReader(pool)
        print(f"Success! Root identified at: {reader.root}")
        print(f"Queries loaded: {list(reader.premade_queries.keys())}")
    except Exception as e:
        print(f"Initialization failed: {e}")