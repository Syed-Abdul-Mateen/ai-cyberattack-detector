import networkx as nx
import matplotlib.pyplot as plt
import os

GRAPH_IMAGE_PATH = "static/graph.png"
os.makedirs("static", exist_ok=True)

# Global graph
attack_graph = nx.DiGraph()

def update_graph(src, dst):
    attack_graph.add_edge(src, dst)
    plt.figure(figsize=(8, 6))
    pos = nx.spring_layout(attack_graph)
    nx.draw(
        attack_graph, pos,
        with_labels=True,
        node_color='skyblue',
        node_size=2000,
        edge_color='red',
        arrows=True,
        font_size=10
    )
    plt.title("🕸️ Attack Path Graph")
    plt.savefig(GRAPH_IMAGE_PATH)
    plt.close()

def clear_graph():
    global attack_graph
    attack_graph.clear()
    # Replace with empty image
    plt.figure(figsize=(8, 6))
    plt.text(0.5, 0.5, 'Graph Cleared', fontsize=18, ha='center')
    plt.axis('off')
    plt.savefig(GRAPH_IMAGE_PATH)
    plt.close()
