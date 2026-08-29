"""AHRAS Hybrid Detection Engine."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sensors.flow_generator import FlowRecord
from feature_engineering import FlowFeatureExtractor, Preprocessor
from detection.signature_engine import SignatureEngine, SignatureResult
from detection.anomaly_engine import AnomalyEngine, AnomalyResult

logger = logging.getLogger("ahras.hybrid")
_SEV = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _higher(a: str, b: str) -> str:
    return a if _SEV.get(a, 0) >= _SEV.get(b, 0) else b


@dataclass
class DetectionResult:
    flow_id: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    attack_type: str
    severity: str
    confidence: float
    signature_result: SignatureResult | None = None
    anomaly_result: AnomalyResult | None = None
    signature_confidence: float = 0.0
    anomaly_score: float = 0.0
    # Populated by the analysis worker from EnrichmentService BEFORE risk
    # scoring, so the risk engine's trust check can use the same resolved
    # org name the dashboard displays instead of a second, less reliable
    # reverse-DNS guess. Empty until the caller sets it.
    organization: str = ""

    def to_dict(self):
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "signature_rule": self.signature_result.rule_id if self.signature_result else None,
            "anomaly_label": self.anomaly_result.label if self.anomaly_result else "Normal",
            "anomaly_score": self.anomaly_result.normalised_score if self.anomaly_result else 0.0,
            "anomaly_raw_score": self.anomaly_result.anomaly_score if self.anomaly_result else 0.0,
            "anomaly_confidence": self.anomaly_result.confidence if self.anomaly_result else 0.0,
            "signature_confidence": self.signature_confidence,
            "organization": self.organization,
        }


class HybridDetectionEngine:
    def __init__(self):
        self.fx = FlowFeatureExtractor()
        self.pp = Preprocessor()
        self.sig = SignatureEngine()
        self.ano = AnomalyEngine()
        logger.info("HybridDetectionEngine ready")

    def analyse(self, flow: FlowRecord) -> DetectionResult:
        vec = self.pp.clean(self.fx.extract(flow))
        sig = self.sig.analyse(flow)
        ano = self.ano.predict(vec)
        fused = self._fuse(sig, ano)
        return DetectionResult(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            protocol=flow.protocol,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            attack_type=fused["attack_type"],
            severity=fused["severity"],
            confidence=fused["confidence"],
            signature_result=sig,
            anomaly_result=ano,
            signature_confidence=float(getattr(sig, "confidence", 0.0) or 0.0),
            anomaly_score=float(getattr(ano, "normalised_score", 0.0) or 0.0),
        )

    def _fuse(self, sig, ano):
        sig_attack = sig.attack_type != "Normal"
        anomaly_attack = bool(ano.is_anomaly)

        if not sig_attack and not anomaly_attack:
            return {"attack_type": "Normal", "severity": "LOW", "confidence": 0.95}

        sig_conf = float(getattr(sig, "confidence", 0.0) or 0.0)
        ano_conf = float(getattr(ano, "confidence", 0.0) or 0.0)

        if sig_attack and anomaly_attack:
            sev = _higher(sig.severity, "HIGH") if sig.severity != "CRITICAL" else "CRITICAL"
            return {
                "attack_type": sig.attack_type,
                "severity": sev,
                "confidence": round(min(sig_conf * 0.6 + ano_conf * 0.4, 1.0), 3),
            }

        if sig_attack:
            return {
                "attack_type": sig.attack_type,
                "severity": sig.severity,
                "confidence": round(min(sig_conf, 1.0), 3),
            }

        sev = "HIGH" if ano.normalised_score >= 0.75 else "MEDIUM"
        return {
            "attack_type": "Anomalous Behaviour",
            "severity": sev,
            "confidence": round(min(ano.confidence, 1.0), 3),
        }