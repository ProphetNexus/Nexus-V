import os
import mysql.connector.pooling
from pathlib import Path
from dotenv import load_dotenv

class DatabasePool:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabasePool, cls).__new__(cls)
            cls._instance._initialize_pool()
        return cls._instance

    def _find_project_root(self) -> Path:
        current = Path(__file__).resolve().parent
        for path in [current] + list(current.parents):
            if (path / 'main.py').exists() and (path / 'configs').is_dir():
                return path
        return Path(__file__).resolve().parent.parent.parent

    def _initialize_pool(self):
        root = self._find_project_root()
        db_env_path = root / 'configs' / 'db.env'
        load_dotenv(dotenv_path=db_env_path)

        db_config = {
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', '3306')),
            'database': os.getenv('DB_NAME'),
            'charset': 'utf8mb4',
            'collation': 'utf8mb4_unicode_ci',
            'use_pure': False 
        }

        try:
            # Combined pool size to accommodate both readers and writers
            self.pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="ethical_tool_pool",
                pool_size=15,
                **db_config
            )
        except mysql.connector.Error as e:
            raise ConnectionError(f"Failed to initialize MySQL Connection Pool: {e}") from e

    def get_connection(self):
        try:
            return self.pool.get_connection()
        except mysql.connector.Error as e:
            raise RuntimeError(f"Database connection request failed: {e}") from e