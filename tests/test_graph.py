"""Tests for graph.engine"""
import pytest
from graph.engine import ThreatGraph


@pytest.fixture
def populated_graph():
    """A graph with a realistic mini-scenario pre-populated."""
    tg = ThreatGraph()
    if not tg.available:
        pytest.skip("networkx not installed")

    # Attacker 1 hits asset, uses MITRE, matches IOC
    tg.ingest_event({
        "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5",
        "severity": "HIGH", "mitre_technique": "T1046",
        "protocol": "TCP", "target_asset_id": "web-server-01",
    })
    tg.ingest_ioc_match("45.33.32.156", "45.33.32.156", "ip")

    # Attacker 2 shares same asset target
    tg.ingest_event({
        "src_ip": "185.220.101.1", "dst_ip": "10.0.0.5",
        "severity": "CRITICAL", "mitre_technique": "T1046",
        "target_asset_id": "web-server-01",
    })
    tg.ingest_ioc_match("185.220.101.1", "45.33.32.156", "ip")  # same IOC indicator

    # Attacker 3 different asset
    tg.ingest_event({
        "src_ip": "5.188.86.172", "dst_ip": "10.0.0.6",
        "severity": "MEDIUM", "target_asset_id": "db-server-02",
    })
    tg.ingest_case("CASE-001", ["45.33.32.156", "185.220.101.1"])
    return tg


class TestThreatGraph:
    def test_graph_available(self, threat_graph):
        if not threat_graph.available:
            pytest.skip("networkx not installed")
        assert threat_graph.available

    def test_ingest_event_adds_nodes(self, populated_graph):
        stats = populated_graph.stats()
        assert stats["total_nodes"] >= 3
        assert stats["nodes_by_type"].get("ip", 0) >= 3

    def test_ingest_event_adds_edges(self, populated_graph):
        stats = populated_graph.stats()
        assert stats["total_edges"] >= 2

    def test_shortest_path_exists(self, populated_graph):
        path = populated_graph.shortest_path("45.33.32.156", "asset:web-server-01")
        assert path is not None
        assert path.length == 1
        assert "45.33.32.156" in path.path
        assert "asset:web-server-01" in path.path

    def test_no_path_returns_none(self, populated_graph):
        result = populated_graph.shortest_path("99.99.99.99", "asset:web-server-01")
        assert result is None

    def test_blast_radius_includes_shared_asset(self, populated_graph):
        br = populated_graph.blast_radius("45.33.32.156", hops=2)
        assert "asset:web-server-01" in br["assets_at_risk"]

    def test_blast_radius_includes_mitre(self, populated_graph):
        br = populated_graph.blast_radius("45.33.32.156", hops=1)
        assert len(br["techniques_observed"]) >= 1

    def test_campaign_clusters_two_attackers(self, populated_graph):
        clusters = populated_graph.find_campaigns(min_cluster_size=2)
        assert len(clusters) >= 1
        biggest = clusters[0]
        assert biggest.ip_count >= 2

    def test_centrality_returns_ranked_list(self, populated_graph):
        ranking = populated_graph.centrality_ranking(top_n=5)
        assert len(ranking) >= 1
        scores = [r["centrality"] for r in ranking]
        assert scores == sorted(scores, reverse=True)

    def test_related_to_ioc(self, populated_graph):
        related = populated_graph.related_to_ioc("45.33.32.156", hops=1)
        assert len(related) >= 1

    def test_prune_stale_removes_nothing_fresh(self, populated_graph):
        removed = populated_graph.prune_stale(ttl=9999)
        assert removed == 0

    def test_clear_empties_graph(self):
        tg = ThreatGraph()
        if not tg.available:
            pytest.skip("networkx not installed")
        tg.ingest_event({"src_ip": "1.2.3.4", "severity": "LOW"})
        tg.clear()
        assert tg.stats()["total_nodes"] == 0
        assert tg.stats()["total_edges"] == 0

    def test_stats_type_counts(self, populated_graph):
        stats = populated_graph.stats()
        assert "nodes_by_type" in stats
        assert stats["nodes_by_type"].get("ip", 0) >= 3
        assert stats["nodes_by_type"].get("asset", 0) >= 1
