from datetime import datetime
from dateutil.relativedelta import relativedelta
from ingestion.database.db_pool import DatabasePool
from ingestion.database.db_reader import DBReader
from graphing.grapher import Make_Graph
from modules.logger import log_manager

class Graph_Manager:
    def __init__(self):
        self.log = log_manager()
        try:
            self.db_pool = DatabasePool()
            self.db_reader = DBReader(self.db_pool)
            self.grapher = Make_Graph()
        except Exception as e:
            self.log.log_critical(f"Graph_Manager failed to initialize: {e}")
            raise

    def get_date_range(self, window_type):
        end_date = datetime.now()
        mapping = {"1m": 1, "3m": 3, "6m": 6, "1y": 12}
        months = mapping.get(window_type, 1)
        start_date = end_date - relativedelta(months=months)
        return start_date.strftime('%Y-%m-%d %H:%M:%S'), end_date.strftime('%Y-%m-%d %H:%M:%S')

    def make_graph(self, query_type, window_type='1m', graph_type='line', smooth=None):
        try:
            start, end = self.get_date_range(window_type)
            data = self.db_reader.run_query(query_type, start_date=start, end_date=end)
            
            if data is None or data.empty:
                self.log.log_warning(f"No data for {query_type} in {window_type} window.")
                return

            self.grapher.set_data(data)
            params = self.grapher.get_params(query_type)
            
            self.grapher.plot(
                graph_type=graph_type,
                x=params.get('x'),
                y=params.get('y'),
                title=f"{params.get('title')} ({window_type})",
                x_label=params.get('x_label'),
                y_label=params.get('y_label'),
                smoothing_window=smooth,
                color=params.get('color'),
                color_map=params.get('color_map')
            )
        except Exception as e:
            self.log.log_error(f"Error in make_graph: {e}")