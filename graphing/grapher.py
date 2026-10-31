import yaml
import plotly.express as px
from pathlib import Path

class Make_Graph:
    def __init__(self):
        self.root = Path(__file__).resolve().parent.parent
        self.config_path = self.root / 'configs' / 'graphs.conf'
        self.data = None
        
        try:
            with open(self.config_path, "r") as f:
                self.config = yaml.safe_load(f).get('graphs', {})
        except Exception as e:
            raise RuntimeError(f"Make_Graph failed to load config from {self.config_path}: {e}")

    
    def set_data(self, data):
        self.data = data

    
    def get_params(self, query_type):
        
        params = self.config.get(query_type)
        
        if params is None:
            raise KeyError(f"Graph parameters for '{query_type}' not found in configuration.")
        return params

    
    def plot(self, graph_type, x, y, title, x_label, y_label, smoothing_window=None, color=None, color_map=None):
        
        if self.data is None:
            raise ValueError("No data provided for plotting.")

        try:
            plot_y = y
            if smoothing_window is not None:
                self.data['Smoothed'] = self.data[y].rolling(window=smoothing_window, min_periods=1).mean()
                plot_y = 'Smoothed'

            match graph_type:
                case "histogram":
                    fig = px.histogram(self.data,
                                       x=x,
                                       y=y,
                                       title=title,
                                       labels={x: x_label, y: y_label},
                                       nbins=10,
                                       color=color,
                                       color_discrete_map=color_map)
                case "line":
                    fig = px.line(self.data,
                                  x=x,
                                  y=plot_y,
                                  title=title,
                                  labels={x: x_label, y: y_label})
                case "bar":
                    fig = px.bar(self.data,
                                 x=x,
                                 y=y,
                                 title=title,
                                 labels={x: x_label, y: y_label},
                                 color=color,
                                 color_discrete_map=color_map)
                case "area":
                    fig = px.area(self.data,
                                  x=x,
                                  y=plot_y,
                                  title=title,
                                  labels={x: x_label, y: y_label},
                                  color=color,
                                  color_discrete_map=color_map,
                                  category_orders={"severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                                  hover_data={'Daily Total': True,
                                              y: True,
                                              x: True,
                                              'severity': True})
                case "scatter":
                    fig = px.scatter(self.data,
                                     x=x,
                                     y=y,
                                     title=title,
                                     labels={x: x_label, y: y_label},
                                     color=color,
                                     color_discrete_map=color_map)
                case _:
                    raise ValueError(f"Unknown graph type: {graph_type}")
            fig.write_html("my_plot.html")
            fig.show()
        except Exception as e:
            raise RuntimeError(f"Plotting failed for {graph_type}: {e}")