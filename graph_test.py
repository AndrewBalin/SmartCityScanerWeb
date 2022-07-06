import plotly.graph_objects as go
import networkx as nx

G = nx.random_geometric_graph(100, 0.125)
nx.draw(G, node_size = 10)

edge_x = []
edge_y = []

for edge in G.edges():
    x0, y0 = G.nodes[edge[0]]['pos']
    x1, y1 = G.nodes[edge[1]]['pos']
    edge_x.append(x0)
    edge_x.append(x1)
    edge_x.append(None)
    edge_y.append(y0)
    edge_y.append(y1)
    edge_y.append(None)

edge_trace = go.Scatter(
    x = edge_x, y = edge_y,
    line = dict(width = 0.5, color = '#888'),
    hoverinfo = 'none',
    mode = 'lines')

node_x = []
node_y = []

for node in G.nodes():
    x, y = G.nodes[node]['pos']
    node_x.append(x)
    node_y.append(y)

node_trace = go.Scatter(
    x = node_x, y = node_y,
    mode = 'markers',
    hoverinfo = 'text',
    marker = dict(
        color = [],
        size = 10
        ),
        line_width = 2)

node_adjacencies = []
node_text = []
for node, adjacencies in enumerate(G.adjacency()):
    node_adjacencies.append(len(adjacencies[1]))
    node_text.append('Connections: ' + str(len(adjacencies[1])))

node_trace.marker.size = node_adjacencies
node_trace.text = node_text

fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                title='<br>Тестовый граф для NTA',
                titlefont_size = 16,
                showlegend = False,
                xaxis=dict(showgrid = False, zeroline = False, showticklabels = False),
                yaxis=dict(showgrid = False, zeroline = False, showticklabels = False))
                )
fig.show()