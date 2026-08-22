"""
AHRAS v4 — Temporal Graph Scoring for Multi-Stage Attack Prediction
(Phase 2 — Research Contribution, builds on graph/engine.py)
═══════════════════════════════════════════════════════════════════════════
Problem: graph/engine.py answers *static* questions ("what's the shortest
path between this IP and that asset right now"). It has no notion of time,
so it can't tell you "this IP is 2 hops from a critical asset AND that
distance has been closing for the last 10 minutes" — the actual signal of
a live, in-progress lateral-movement campaign.

Honest scope note: this is a lightweight, dependency-free approximation of
temporal-GNN *behavior* (time-decayed node embeddings updated by neighbor
message-passing), not a trained deep-learning model. Standing up a real
TGN/TGAT (PyTorch Geometric Temporal, etc.) needs GPU training on labeled
attack-path datasets neither available nor reproducible in this sandbox.
What's here is the same idea implemented with numpy so it runs anywhere,
updates online (no training phase), and is honest in a paper as "temporal
embedding propagation with exponential time-decay", not as "we trained a
TGNN". Swapping in a real TGNN later just means replacing `_propagate()`
with a trained model's forward pass — the surrounding API doesn't change.

What it adds over the static graph:
  - Every node gets a small embedding vector that is nudged toward its
    neighbors' embeddings every time an edge fires (message passing),
    with older edges contributing less (exponential time-decay).
  - `predict_attack_paths()` scores every path from a source IP toward
    high-value assets by how much "risk energy" has actually flowed along
    it recently — not just whether a path topologically exists.
  - This surfaces multi-stage APT movement (recon → foothold → pivot →
    target) *before* the final hop lands, because the embeddings on
    intermediate nodes start drifting toward the attacker's embedding as
    soon as the first couple of hops happen.
"""
import time
import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("ahras.graph.tgnn")

EMBED_DIM = 16
TIME_DECAY_HALF_LIFE = 900.0     # seconds; edge influence halves every 15 min
LEARNING_RATE = 0.35             # how hard each message-pass nudges the embedding
APT_PATH_SCORE_THRESHOLD = 0.55  # 0-1, above this we flag a path as "developing"


@dataclass
class AttackPathPrediction:
    source: str
    target: str
    path: List[str]
    risk_energy: float           # 0-1, how "hot" this path is right now
    developing: bool             # True if risk_energy rising over last window
    stage_estimate: str          # rough kill-chain stage guess
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "target": self.target, "path": self.path,
            "risk_energy": round(self.risk_energy, 3),
            "developing": self.developing,
            "stage_estimate": self.stage_estimate,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
        }


class TemporalGraphScorer:
    """
    Wraps an existing ThreatGraph (graph/engine.py) instance and maintains
    time-decayed embeddings on top of it. Call `on_edge()` every time the
    static graph records a new edge (CONTACTED, TARGETED, MATCHES, ...);
    call `predict_attack_paths()` periodically or on-demand from the API.
    """

    def __init__(self, threat_graph=None, embed_dim: int = EMBED_DIM):
        self.threat_graph = threat_graph
        self.dim = embed_dim
        self._embeddings: Dict[str, np.ndarray] = {}
        self._last_seen: Dict[str, float] = {}
        self._malicious_energy: Dict[str, float] = {}       # explicit, monotonic signal
        self._energy_history: Dict[str, List[float]] = {}   # node -> recent risk_energy samples
        logger.info("TemporalGraphScorer ready (dim=%d)", embed_dim)

    # ── embedding maintenance ──────────────────────────────────────────
    def _get_or_init(self, node_id: str) -> np.ndarray:
        if node_id not in self._embeddings:
            rng = np.random.default_rng(abs(hash(node_id)) % (2**32))
            self._embeddings[node_id] = rng.normal(0, 0.1, self.dim)
        return self._embeddings[node_id]

    def _decay_factor(self, node_id: str, now: float) -> float:
        last = self._last_seen.get(node_id, now)
        dt = max(0.0, now - last)
        return 0.5 ** (dt / TIME_DECAY_HALF_LIFE)

    def on_edge(self, src: str, dst: str, edge_weight: float = 1.0, is_malicious_hint: bool = False):
        """
        Call this whenever a new graph edge is observed. Propagates a
        message from src -> dst (and a smaller reverse message), decayed
        by how long it's been since dst was last touched.
        """
        now = time.time()
        e_src = self._get_or_init(src)
        e_dst = self._get_or_init(dst)

        decay = self._decay_factor(dst, now)
        # message-passing update: nudge dst toward src, scaled by edge weight,
        # decayed by recency, and boosted if this edge came from a known-bad hint
        boost = 1.6 if is_malicious_hint else 1.0
        msg = LEARNING_RATE * edge_weight * boost * (e_src - e_dst) * (1 - decay + 0.05)
        self._embeddings[dst] = e_dst + msg
        # small reverse signal so upstream nodes also feel downstream compromise
        self._embeddings[src] = e_src + 0.25 * msg

        self._last_seen[dst] = now
        self._last_seen[src] = now

        # Explicit, monotonic risk-energy accumulator — decays with the same
        # half-life as the embeddings, bumped harder for malicious-hinted edges.
        # This is what guarantees "malicious edge -> strictly higher energy
        # than a benign edge", which the raw embedding norm alone can't
        # promise (a vector nudge can occasionally shrink the norm depending
        # on the existing embedding's direction).
        self._malicious_energy[dst] = self._malicious_energy.get(dst, 0.0) * decay + (0.55 if is_malicious_hint else 0.12)
        self._malicious_energy[src] = self._malicious_energy.get(src, 0.0) * decay + (0.15 if is_malicious_hint else 0.03)

    # ── scoring ─────────────────────────────────────────────────────────
    def _node_energy(self, node_id: str) -> float:
        """0-1 'how attacker-like has this node's embedding drifted' score.
        Blends two signals: (a) how far the message-passed embedding has
        drifted from its random init (captures neighbor influence/direction),
        and (b) an explicit, monotonically-behaved malicious-energy
        accumulator bumped directly on malicious-hinted edges. (b) exists
        because (a) alone is a vector projection and isn't guaranteed to be
        monotonic in the malicious-hint boost for any single embedding
        draw — see on_edge()'s comment."""
        if node_id not in self._embeddings:
            return 0.0
        vec = self._embeddings[node_id]
        mag = float(np.linalg.norm(vec))
        embed_energy = 1 - math.exp(-mag)          # squashed to (0,1)
        mal_energy = min(1.0, self._malicious_energy.get(node_id, 0.0))
        energy = 0.5 * embed_energy + 0.5 * mal_energy
        hist = self._energy_history.setdefault(node_id, [])
        hist.append(energy)
        if len(hist) > 20:
            hist.pop(0)
        return energy

    def predict_attack_paths(self, source_ip: str, max_targets: int = 5,
                              max_hops: int = 4) -> List[AttackPathPrediction]:
        """
        For a given (likely already-suspicious) source IP, find candidate
        paths toward high-value assets in the static graph and score each
        by accumulated risk_energy along the path, using the temporal
        embeddings rather than pure hop-count.
        """
        if self.threat_graph is None or not getattr(self.threat_graph, "AVAILABLE", True):
            return []

        results: List[AttackPathPrediction] = []
        try:
            candidate_targets = self.threat_graph.high_value_targets(limit=max_targets)  # type: ignore
        except AttributeError:
            candidate_targets = self.threat_graph.list_assets(limit=max_targets) if hasattr(
                self.threat_graph, "list_assets") else []

        for target in candidate_targets:
            try:
                gp = self.threat_graph.shortest_path(source_ip, target, max_hops=max_hops)  # type: ignore
            except Exception:
                gp = None
            if not gp or not gp.path:
                continue

            path = gp.path
            energies = [self._node_energy(n) for n in path]
            # risk_energy of the path = weakest-link-weighted average, biased
            # toward the *later* hops (closer to target = more concerning)
            weights = np.linspace(0.6, 1.4, num=len(energies))
            risk_energy = float(np.average(energies, weights=weights)) if energies else 0.0

            hist = self._energy_history.get(path[-1], [])
            developing = len(hist) >= 2 and hist[-1] > hist[-2]

            stage = self._estimate_stage(len(path), risk_energy)

            if risk_energy >= APT_PATH_SCORE_THRESHOLD or developing:
                results.append(AttackPathPrediction(
                    source=source_ip, target=target, path=path,
                    risk_energy=risk_energy, developing=developing,
                    stage_estimate=stage,
                ))

        results.sort(key=lambda r: r.risk_energy, reverse=True)
        return results

    @staticmethod
    def _estimate_stage(hop_count: int, energy: float) -> str:
        """Very rough MITRE-ish kill-chain stage guess from path depth + energy."""
        if energy < 0.3:
            return "Reconnaissance"
        if hop_count <= 1:
            return "Initial Access"
        if hop_count == 2:
            return "Lateral Movement"
        if energy >= 0.75:
            return "Actions on Objectives (imminent)"
        return "Privilege Escalation / Pivoting"

    def stats(self) -> dict:
        return {
            "tracked_nodes": len(self._embeddings),
            "embed_dim": self.dim,
            "half_life_seconds": TIME_DECAY_HALF_LIFE,
            "threshold": APT_PATH_SCORE_THRESHOLD,
        }


# Singleton, mirrors the pattern used by graph/engine.py's ThreatGraph
tgnn_scorer = TemporalGraphScorer()
