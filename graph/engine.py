"""
AHRAS v4 -- Graph-based Threat Correlation  (Phase 1 -- Research Contribution)
================================================================================
Problem: correlation/engine.py uses fixed sequential rules (e.g. "Port Scan
then Traffic Flood within 10 min from same IP = APT pattern"). This catches
known patterns but misses multi-hop relationships: an IP that shares
infrastructure with a known-bad IOC, or two seemingly unrelated IPs that
both touch the same compromised asset.

Solution: a typed property graph over all security entities.
Nodes:  ip, asset, ioc, mitre_technique, case
Edges:  CONTACTED (ip->ip via flow), TARGETED (ip->asset), MATCHES (ip->ioc),
        USED_TECHNIQUE (ip->mitre), INVOLVED_IN (ip->case)

This lets us answer questions the rule engine cannot:
  - "What's the shortest path between this IP and our crown-jewel asset?"
  - "Which IPs are within 2 hops of a known-malicious IOC?"
  - "What's the blast radius if this IP is compromised?" (graph centrality)
  - "Are these 3 unrelated alerts actually one campaign?" (connected components)

Built on networkx (pure Python, already a common dependency, no GPU/server
needed) -- defensible in a paper as "graph-theoretic threat correlation
using centrality and shortest-path analysis", and fast enough for a
single-host graph of a few thousand nodes.
"""
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

logger = logging.getLogger("ahras.graph")

MAX_NODES = 5000          # cap to keep memory/perf bounded on a laptop
NODE_TTL_SECONDS = 86400  # prune nodes untouched for 24h


@dataclass
class GraphPath:
    source: str
    target: str
    path: List[str]
    length: int
    edge_types: List[str]

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "path": self.path, "length": self.length,
                "edge_types": self.edge_types}


@dataclass
class CampaignCluster:
    cluster_id: str
    nodes: List[str]
    ip_count: int
    asset_count: int
    ioc_count: int
    risk_density: float    # avg degree -- how interconnected the cluster is

    def to_dict(self) -> dict:
        return {"cluster_id": self.cluster_id, "nodes": self.nodes,
                "ip_count": self.ip_count, "asset_count": self.asset_count,
                "ioc_count": self.ioc_count, "risk_density": round(self.risk_density, 2)}


class ThreatGraph:
    """
    In-memory threat relationship graph. Not persisted to MongoDB by
    design -- it is a derived view rebuilt/updated from events, IOCs,
    cases, and correlation incidents as they happen, and is cheap to
    rebuild from scratch if needed.
    """

    def __init__(self):
        if not NETWORKX_AVAILABLE:
            logger.warning("networkx not installed -- ThreatGraph running in no-op mode")
            self.G = None
        else:
            self.G = nx.MultiDiGraph()
        self._last_touched: Dict[str, float] = {}
        self._total_edges_added = 0

    @property
    def available(self) -> bool:
        return self.G is not None

    # -- Node/edge ingestion -------------------------------------------------
    def add_node(self, node_id: str, node_type: str, **attrs):
        if not self.available:
            return
        self.G.add_node(node_id, type=node_type, **attrs)
        self._last_touched[node_id] = time.time()
        if self.G.number_of_nodes() > MAX_NODES:
            self._prune_oldest()

    def add_edge(self, src: str, dst: str, edge_type: str, **attrs):
        if not self.available:
            return
        if src not in self.G:
            self.add_node(src, "unknown")
        if dst not in self.G:
            self.add_node(dst, "unknown")
        self.G.add_edge(src, dst, type=edge_type, timestamp=time.time(), **attrs)
        self._last_touched[src] = time.time()
        self._last_touched[dst] = time.time()
        self._total_edges_added += 1

    def ingest_event(self, event: dict):
        """Wire an AHRAS security event into the graph: ip -> asset,
        ip -> mitre technique."""
        if not self.available:
            return
        src_ip = event.get("src_ip")
        if not src_ip:
            return
        self.add_node(src_ip, "ip", last_severity=event.get("severity", "LOW"))

        dst_ip = event.get("dst_ip")
        if dst_ip and dst_ip != src_ip:
            self.add_edge(src_ip, dst_ip, "CONTACTED", protocol=event.get("protocol", ""))

        technique = event.get("mitre_technique")
        if technique:
            self.add_node(f"mitre:{technique}", "mitre_technique")
            self.add_edge(src_ip, f"mitre:{technique}", "USED_TECHNIQUE")

        asset_id = event.get("target_asset_id")
        if asset_id:
            self.add_node(f"asset:{asset_id}", "asset")
            self.add_edge(src_ip, f"asset:{asset_id}", "TARGETED")

    def ingest_ioc_match(self, src_ip: str, indicator: str, ioc_type: str):
        if not self.available or not src_ip:
            return
        self.add_node(src_ip, "ip")
        self.add_node(f"ioc:{indicator}", "ioc", ioc_type=ioc_type)
        self.add_edge(src_ip, f"ioc:{indicator}", "MATCHES")

    def ingest_case(self, case_id: str, affected_ips: List[str]):
        if not self.available or not case_id:
            return
        self.add_node(f"case:{case_id}", "case")
        for ip in affected_ips or []:
            self.add_node(ip, "ip")
            self.add_edge(ip, f"case:{case_id}", "INVOLVED_IN")

    # -- Queries --------------------------------------------------------------
    def shortest_path(self, source: str, target: str) -> Optional[GraphPath]:
        if not self.available or source not in self.G or target not in self.G:
            return None
        try:
            path = nx.shortest_path(self.G.to_undirected(), source, target)
        except nx.NetworkXNoPath:
            return None
        edge_types = []
        for i in range(len(path) - 1):
            data = self.G.get_edge_data(path[i], path[i + 1]) or self.G.get_edge_data(path[i + 1], path[i])
            if data:
                first_edge = list(data.values())[0]
                edge_types.append(first_edge.get("type", "?"))
            else:
                edge_types.append("?")
        return GraphPath(source=source, target=target, path=path,
                          length=len(path) - 1, edge_types=edge_types)

    def neighbors_within_hops(self, node: str, hops: int = 2) -> Dict[str, int]:
        """Returns {node_id: distance} for all nodes within N hops --
        used to answer 'what's within blast radius of this IP'."""
        if not self.available or node not in self.G:
            return {}
        und = self.G.to_undirected()
        lengths = nx.single_source_shortest_path_length(und, node, cutoff=hops)
        lengths.pop(node, None)
        return lengths

    def blast_radius(self, ip: str, hops: int = 2) -> dict:
        """Summarizes what assets/IOCs/IPs are reachable from a given IP
        within N hops -- 'if this IP is compromised, what's at risk?'"""
        reachable = self.neighbors_within_hops(ip, hops)
        assets, iocs, ips, mitre = [], [], [], []
        for node_id in reachable:
            ntype = self.G.nodes[node_id].get("type", "unknown")
            if ntype == "asset": assets.append(node_id)
            elif ntype == "ioc": iocs.append(node_id)
            elif ntype == "ip": ips.append(node_id)
            elif ntype == "mitre_technique": mitre.append(node_id)
        return {
            "source_ip": ip, "hops": hops, "total_reachable": len(reachable),
            "assets_at_risk": assets, "related_iocs": iocs,
            "related_ips": ips, "techniques_observed": mitre,
        }

    def centrality_ranking(self, top_n: int = 10) -> List[dict]:
        """Betweenness centrality -- which nodes sit on the most paths
        between other nodes. High centrality IP = pivot point / hub,
        worth investigating even if its own risk score looks moderate."""
        if not self.available or self.G.number_of_nodes() < 2:
            return []
        und = self.G.to_undirected()
        try:
            centrality = nx.betweenness_centrality(und, k=min(100, und.number_of_nodes()))
        except Exception as e:
            logger.warning(f"Centrality calculation failed: {e}")
            return []
        ranked = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [
            {"node": n, "type": self.G.nodes[n].get("type", "unknown"),
             "centrality": round(c, 4)}
            for n, c in ranked if c > 0
        ]

    def find_campaigns(self, min_cluster_size: int = 3) -> List[CampaignCluster]:
        """Connected-component analysis: groups of IPs/assets/IOCs that
        are linked together, even if no single rule fired for them.
        A cluster spanning multiple IPs + a shared IOC or asset often
        indicates one coordinated campaign rather than isolated events."""
        if not self.available:
            return []
        und = self.G.to_undirected()
        clusters = []
        for i, component in enumerate(nx.connected_components(und)):
            if len(component) < min_cluster_size:
                continue
            sub = und.subgraph(component)
            ip_count = sum(1 for n in component if self.G.nodes[n].get("type") == "ip")
            asset_count = sum(1 for n in component if self.G.nodes[n].get("type") == "asset")
            ioc_count = sum(1 for n in component if self.G.nodes[n].get("type") == "ioc")
            density = (2 * sub.number_of_edges()) / max(1, sub.number_of_nodes())
            clusters.append(CampaignCluster(
                cluster_id=f"CLUSTER-{i+1}", nodes=list(component),
                ip_count=ip_count, asset_count=asset_count, ioc_count=ioc_count,
                risk_density=density,
            ))
        clusters.sort(key=lambda c: c.ip_count + c.asset_count, reverse=True)
        return clusters

    def related_to_ioc(self, indicator: str, hops: int = 2) -> List[str]:
        """All IPs within N hops of a known-bad IOC -- proactive hunting."""
        node_id = f"ioc:{indicator}"
        reachable = self.neighbors_within_hops(node_id, hops)
        return [n for n in reachable if self.G.nodes[n].get("type") == "ip"]

    # -- Maintenance ------------------------------------------------------
    def _prune_oldest(self, remove_count: int = 200):
        if not self.available:
            return
        oldest = sorted(self._last_touched.items(), key=lambda x: x[1])[:remove_count]
        for node_id, _ in oldest:
            if node_id in self.G:
                self.G.remove_node(node_id)
            self._last_touched.pop(node_id, None)
        logger.info(f"Graph pruned {len(oldest)} oldest nodes (cap={MAX_NODES})")

    def prune_stale(self, ttl: int = NODE_TTL_SECONDS) -> int:
        if not self.available:
            return 0
        now = time.time()
        stale = [n for n, t in self._last_touched.items() if now - t > ttl]
        for node_id in stale:
            if node_id in self.G:
                self.G.remove_node(node_id)
            self._last_touched.pop(node_id, None)
        return len(stale)

    def clear(self):
        if self.available:
            self.G.clear()
        self._last_touched.clear()
        self._total_edges_added = 0

    def stats(self) -> dict:
        if not self.available:
            return {"available": False, "reason": "networkx not installed"}
        type_counts: Dict[str, int] = {}
        for _, data in self.G.nodes(data=True):
            t = data.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        return {
            "available": True,
            "total_nodes": self.G.number_of_nodes(),
            "total_edges": self.G.number_of_edges(),
            "total_edges_ever_added": self._total_edges_added,
            "nodes_by_type": type_counts,
            "max_nodes_cap": MAX_NODES,
        }
