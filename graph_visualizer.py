import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk

class GraphVisualizer:
    def __init__(self, canvas):
        self.canvas = canvas

    def visualize(self, data):
        G = nx.Graph()

        # Add nodes and edges based on data
        for key, value in data.items():
            G.add_node(key)
            if isinstance(value, dict):
                for subkey in value.keys():
                    G.add_edge(key, subkey)

        fig = plt.Figure(figsize=(6, 4), dpi=100)
        ax = fig.add_subplot(111)
        nx.draw(G, ax=ax, with_labels=True, node_color='lightblue', node_size=500, font_size=10)
        ax.set_title("OSINT Relationship Graph")

        canvas = FigureCanvasTkAgg(fig, master=self.canvas)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
