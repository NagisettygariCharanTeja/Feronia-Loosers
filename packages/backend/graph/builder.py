import networkx as nx

from schemas.graph_conventions import EDGE_RELATION, EDGE_PORT, EDGE_PROTOCOL

_GRAPH: nx.DiGraph = None


def build_graph(infrastructure: dict) -> nx.DiGraph:
    global _GRAPH
    _GRAPH = nx.DiGraph()

    for resource in infrastructure["resources"]:
        node_id = resource["id"]
        attrs = {k: v for k, v in resource.items() if k != "id"}
        _GRAPH.add_node(node_id, **attrs)

    for rel in infrastructure.get("relationships", []):
        edge_attrs = {EDGE_RELATION: rel["relation"]}
        if "port" in rel:
            edge_attrs[EDGE_PORT] = rel["port"]
        if "protocol" in rel:
            edge_attrs[EDGE_PROTOCOL] = rel["protocol"]
        _GRAPH.add_edge(rel["source"], rel["target"], **edge_attrs)

    return _GRAPH


def get_graph() -> nx.DiGraph:
    return _GRAPH
