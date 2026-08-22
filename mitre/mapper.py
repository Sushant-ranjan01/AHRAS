"""AHRAS — MITRE ATT&CK Mapper
Maps detected attack types to MITRE ATT&CK techniques, tactics, and provides
enrichment data for professional SOC reporting.
"""
from dataclasses import dataclass
from typing import List, Optional, Dict

@dataclass
class MitreResult:
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    subtechnique_id: Optional[str]
    subtechnique_name: Optional[str]
    description: str
    url: str
    severity_boost: float = 0.0

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "subtechnique_id": self.subtechnique_id,
            "subtechnique_name": self.subtechnique_name,
            "description": self.description,
            "url": self.url,
        }

# Complete MITRE ATT&CK mapping database
_ATTACK_MAP: Dict[str, MitreResult] = {
    "SSH Bruteforce": MitreResult(
        technique_id="T1110", technique_name="Brute Force",
        tactic="Credential Access", tactic_id="TA0006",
        subtechnique_id="T1110.001", subtechnique_name="Password Guessing",
        description="Adversaries use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        url="https://attack.mitre.org/techniques/T1110/001/", severity_boost=0.5
    ),
    "Port Scan": MitreResult(
        technique_id="T1046", technique_name="Network Service Discovery",
        tactic="Discovery", tactic_id="TA0007",
        subtechnique_id=None, subtechnique_name=None,
        description="Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        url="https://attack.mitre.org/techniques/T1046/", severity_boost=0.3
    ),
    "Traffic Flood": MitreResult(
        technique_id="T1498", technique_name="Network Denial of Service",
        tactic="Impact", tactic_id="TA0040",
        subtechnique_id="T1498.001", subtechnique_name="Direct Network Flood",
        description="Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources.",
        url="https://attack.mitre.org/techniques/T1498/001/", severity_boost=1.0
    ),
    "UDP Flood": MitreResult(
        technique_id="T1498", technique_name="Network Denial of Service",
        tactic="Impact", tactic_id="TA0040",
        subtechnique_id="T1498.001", subtechnique_name="Direct Network Flood",
        description="UDP flood attack targeting network availability using high-volume UDP packets.",
        url="https://attack.mitre.org/techniques/T1498/001/", severity_boost=0.8
    ),
    "DNS Amplification": MitreResult(
        technique_id="T1498", technique_name="Network Denial of Service",
        tactic="Impact", tactic_id="TA0040",
        subtechnique_id="T1498.002", subtechnique_name="Reflection Amplification",
        description="Adversaries may attempt to cause a denial of service by reflecting a high-volume of network traffic to a target.",
        url="https://attack.mitre.org/techniques/T1498/002/", severity_boost=0.9
    ),
    "High Packet Rate": MitreResult(
        technique_id="T1498", technique_name="Network Denial of Service",
        tactic="Impact", tactic_id="TA0040",
        subtechnique_id=None, subtechnique_name=None,
        description="Abnormally high packet rate indicating potential flooding or scanning activity.",
        url="https://attack.mitre.org/techniques/T1498/", severity_boost=0.3
    ),
    "Anomalous Behaviour": MitreResult(
        technique_id="T1071", technique_name="Application Layer Protocol",
        tactic="Command and Control", tactic_id="TA0011",
        subtechnique_id=None, subtechnique_name=None,
        description="ML anomaly detection flagged unusual traffic patterns consistent with C2 communication or data exfiltration.",
        url="https://attack.mitre.org/techniques/T1071/", severity_boost=0.4
    ),
    "SQL Injection": MitreResult(
        technique_id="T1190", technique_name="Exploit Public-Facing Application",
        tactic="Initial Access", tactic_id="TA0001",
        subtechnique_id=None, subtechnique_name=None,
        description="Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, data, or commands.",
        url="https://attack.mitre.org/techniques/T1190/", severity_boost=1.5
    ),
    "XSS": MitreResult(
        technique_id="T1059", technique_name="Command and Scripting Interpreter",
        tactic="Execution", tactic_id="TA0002",
        subtechnique_id="T1059.007", subtechnique_name="JavaScript",
        description="Cross-site scripting attack injecting malicious scripts into web content.",
        url="https://attack.mitre.org/techniques/T1059/007/", severity_boost=0.8
    ),
    "DNS Tunneling": MitreResult(
        technique_id="T1071", technique_name="Application Layer Protocol",
        tactic="Command and Control", tactic_id="TA0011",
        subtechnique_id="T1071.004", subtechnique_name="DNS",
        description="Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection.",
        url="https://attack.mitre.org/techniques/T1071/004/", severity_boost=1.2
    ),
    "Beaconing": MitreResult(
        technique_id="T1071", technique_name="Application Layer Protocol",
        tactic="Command and Control", tactic_id="TA0011",
        subtechnique_id=None, subtechnique_name=None,
        description="Regular interval communication pattern indicating C2 beacon activity.",
        url="https://attack.mitre.org/techniques/T1071/", severity_boost=1.3
    ),
    "Lateral Movement": MitreResult(
        technique_id="T1021", technique_name="Remote Services",
        tactic="Lateral Movement", tactic_id="TA0008",
        subtechnique_id=None, subtechnique_name=None,
        description="Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
        url="https://attack.mitre.org/techniques/T1021/", severity_boost=1.5
    ),
    "Data Exfiltration": MitreResult(
        technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration", tactic_id="TA0010",
        subtechnique_id=None, subtechnique_name=None,
        description="Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        url="https://attack.mitre.org/techniques/T1041/", severity_boost=2.0
    ),
    "Ransomware": MitreResult(
        technique_id="T1486", technique_name="Data Encrypted for Impact",
        tactic="Impact", tactic_id="TA0040",
        subtechnique_id=None, subtechnique_name=None,
        description="Adversaries may encrypt data on target systems to interrupt availability to system and network resources.",
        url="https://attack.mitre.org/techniques/T1486/", severity_boost=3.0
    ),
    "Malware": MitreResult(
        technique_id="T1204", technique_name="User Execution",
        tactic="Execution", tactic_id="TA0002",
        subtechnique_id="T1204.002", subtechnique_name="Malicious File",
        description="An adversary may rely upon a user opening a malicious file in order to gain execution.",
        url="https://attack.mitre.org/techniques/T1204/002/", severity_boost=2.0
    ),
    "Credential Attack": MitreResult(
        technique_id="T1110", technique_name="Brute Force",
        tactic="Credential Access", tactic_id="TA0006",
        subtechnique_id="T1110.003", subtechnique_name="Password Spraying",
        description="Adversaries may use a single or small list of commonly used passwords against many different accounts.",
        url="https://attack.mitre.org/techniques/T1110/003/", severity_boost=0.7
    ),
    "C2 Communication": MitreResult(
        technique_id="T1095", technique_name="Non-Application Layer Protocol",
        tactic="Command and Control", tactic_id="TA0011",
        subtechnique_id=None, subtechnique_name=None,
        description="Adversaries may use a non-application layer protocol for communication between host and C2 server.",
        url="https://attack.mitre.org/techniques/T1095/", severity_boost=1.8
    ),
}

_DEFAULT = MitreResult(
    technique_id="T1040", technique_name="Network Sniffing",
    tactic="Discovery", tactic_id="TA0007",
    subtechnique_id=None, subtechnique_name=None,
    description="Anomalous network activity detected; further investigation required.",
    url="https://attack.mitre.org/techniques/T1040/", severity_boost=0.0
)

class MitreMapper:
    """Maps attack types to MITRE ATT&CK techniques."""

    def map(self, attack_type: str) -> Optional[MitreResult]:
        if attack_type == "Normal":
            return None
        # Direct match
        if attack_type in _ATTACK_MAP:
            return _ATTACK_MAP[attack_type]
        # Fuzzy match
        attack_lower = attack_type.lower()
        for key, val in _ATTACK_MAP.items():
            if key.lower() in attack_lower or attack_lower in key.lower():
                return val
        return _DEFAULT

    def all_techniques(self) -> List[dict]:
        return [{"attack_type": k, **v.to_dict()} for k, v in _ATTACK_MAP.items()]

    def techniques_by_tactic(self) -> Dict[str, List[dict]]:
        result: Dict[str, List[dict]] = {}
        for k, v in _ATTACK_MAP.items():
            tactic = v.tactic
            if tactic not in result:
                result[tactic] = []
            result[tactic].append({"attack_type": k, **v.to_dict()})
        return result
