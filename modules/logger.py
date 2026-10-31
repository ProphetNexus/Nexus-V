import logging
import yaml
from pathlib import Path
from logging.handlers import RotatingFileHandler

class log_manager:
    def __init__(self):
        self.root = Path(__file__).resolve().parent.parent
        self.config_path = self.root / 'configs' / 'logs.conf'
        default_log_dir = self.root / 'logs'

        self.settings = self._load_config()
        
        custom_dir = self.settings.get('log_directory')
        self.log_path = Path(custom_dir) if custom_dir else default_log_dir
        self.log_path.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("NexusV")
        self.logger.setLevel(logging.DEBUG) 
        
        if not self.logger.handlers:
            self._setup_handlers()

    def _load_config(self):
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    data = yaml.safe_load(f)
                    return data.get('logging', {}) if data else {}
            except Exception:
                pass
        return {}

    def _setup_handlers(self):
        formatter = logging.Formatter('%(levelname)s : %(asctime)s : %(message)s', 
                                      datefmt='%Y-%m-%d %H:%M:%S')

        levels = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL
        }

        for name, level in levels.items():
            log_file = self.log_path / f"{name}.log"
            handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=2)
            handler.setLevel(level)
            handler.setFormatter(formatter)
            handler.addFilter(lambda record, lvl=level: record.levelno == lvl)
            self.logger.addHandler(handler)

    def log_debug(self, msg): self.logger.debug(msg)
    def log_info(self, msg): self.logger.info(msg)
    def log_warning(self, msg): self.logger.warning(msg)
    def log_error(self, msg): self.logger.error(msg)
    def log_critical(self, msg): self.logger.critical(msg)
    