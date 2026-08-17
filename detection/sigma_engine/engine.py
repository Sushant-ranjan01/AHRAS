"""
AHRAS v4 — Sigma Rule Engine
(Phase 2 — Structural Addition)
═══════════════════════════════════════════════════════════════════════════
Problem: detection/signature_engine/engine.py is fast but its rules are
hand-written Python — every new detection idea means a code change and a
redeploy. There's also no way to consume the huge public library of
community Sigma rules (https://github.com/SigmaHQ/sigma), which is the
de-facto standard interchange format SOC teams already share detections
in.

Solution: a small, dependency-light Sigma rule loader + matcher that runs
*alongside* the existing signature engine (it doesn't replace it). It
understands the common subset of Sigma's `detection:` block:
  - equality:            field: value
  - contains:             field|contains: value
  - starts/ends with:     field|startswith / field|endswith: value
  - list-of-values (OR):  field: [v1, v2, v3]
  - AND across fields inside one selection block
  - condition: "selection" / "selection1 and selection2" / "1 of them"
This covers the overwhelming majority of real-world Sigma rules without
pulling in a full Sigma-to-backend compiler (pySigma), keeping this
dependency-free beyond PyYAML.

Rules can come from three places: bundled .yml files in this package's
`rules/` folder, uploaded via the API, or generated automatically by
honeypot/deception_feedback.py from live attacker interactions.
"""
import glob
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger("ahras.sigma")

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


@dataclass
class SigmaMatch:
    rule_id: str
    title: str
    level: str
    tags: List[str]
    matched_selection: str

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "title": self.title, "level": self.level,
                "tags": self.tags, "matched_selection": self.matched_selection}


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    level: str
    tags: List[str]
    detection: Dict[str, Any]
    condition: str
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_yaml_dict(cls, d: dict) -> "SigmaRule":
        detection = d.get("detection", {}) or {}
        return cls(
            rule_id=str(d.get("id") or d.get("title", "unnamed")).replace(" ", "_"),
            title=d.get("title", "Untitled Sigma Rule"),
            level=d.get("level", "medium"),
            tags=d.get("tags", []) or [],
            detection=detection,
            condition=detection.get("condition", "selection"),
            raw=d,
        )


def _field_matches(event: dict, key: str, expected: Any) -> bool:
    """Handles the field|modifier syntax and list-of-values OR semantics."""
    if "|" in key:
        field_name, modifier = key.split("|", 1)
    else:
        field_name, modifier = key, "equals"

    actual = event.get(field_name)
    if actual is None:
        return False
    actual_str = str(actual).lower()

    values = expected if isinstance(expected, list) else [expected]
    for v in values:
        v_str = str(v).lower()
        if modifier == "contains" and v_str in actual_str:
            return True
        if modifier == "startswith" and actual_str.startswith(v_str):
            return True
        if modifier == "endswith" and actual_str.endswith(v_str):
            return True
        if modifier == "equals" and actual_str == v_str:
            return True
    return False


def _selection_matches(event: dict, selection: dict) -> bool:
    """All fields inside one selection block must match (AND)."""
    return all(_field_matches(event, k, v) for k, v in selection.items())


def _evaluate_condition(detection: Dict[str, Any], condition: str, event: dict) -> Optional[str]:
    """
    Supports: a single selection name, 'sel1 and sel2', 'sel1 or sel2',
    and '1 of them' / 'all of them'. Returns the name of the first
    selection that matched, or None.
    """
    named = {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}
    cond = condition.strip().lower()

    if cond in ("1 of them", "any of them"):
        for name, sel in named.items():
            if _selection_matches(event, sel):
                return name
        return None
    if cond == "all of them":
        if named and all(_selection_matches(event, sel) for sel in named.values()):
            return "+".join(named.keys())
        return None
    if " and " in cond:
        parts = [p.strip() for p in cond.split(" and ")]
        if all(p in named and _selection_matches(event, named[p]) for p in parts):
            return "+".join(parts)
        return None
    if " or " in cond:
        for p in [p.strip() for p in cond.split(" or ")]:
            if p in named and _selection_matches(event, named[p]):
                return p
        return None
    # single selection name
    if cond in named and _selection_matches(event, named[cond]):
        return cond
    return None


class SigmaEngine:
    def __init__(self):
        self.rules: Dict[str, SigmaRule] = {}
        if YAML_AVAILABLE:
            self._load_bundled_rules()
        else:
            logger.warning("PyYAML not installed — Sigma engine running with 0 rules until "
                            "`pip install pyyaml` or rules are added programmatically.")

    def _load_bundled_rules(self):
        os.makedirs(RULES_DIR, exist_ok=True)
        for path in glob.glob(os.path.join(RULES_DIR, "*.yml")) + glob.glob(os.path.join(RULES_DIR, "*.yaml")):
            try:
                self.load_rule_file(path)
            except Exception as exc:
                logger.error("Failed to load Sigma rule %s: %s", path, exc)
        logger.info("SigmaEngine loaded %d rule(s) from %s", len(self.rules), RULES_DIR)

    def load_rule_file(self, path: str) -> Optional[SigmaRule]:
        if not YAML_AVAILABLE:
            raise RuntimeError("PyYAML not installed")
        with open(path) as f:
            d = yaml.safe_load(f)
        if not d:
            return None
        rule = SigmaRule.from_yaml_dict(d)
        self.rules[rule.rule_id] = rule
        return rule

    def load_rule_yaml_string(self, yaml_text: str) -> SigmaRule:
        if not YAML_AVAILABLE:
            raise RuntimeError("PyYAML not installed")
        d = yaml.safe_load(yaml_text)
        rule = SigmaRule.from_yaml_dict(d)
        self.rules[rule.rule_id] = rule
        return rule

    def add_rule_dict(self, d: dict) -> SigmaRule:
        rule = SigmaRule.from_yaml_dict(d)
        self.rules[rule.rule_id] = rule
        return rule

    def match(self, event: dict) -> List[SigmaMatch]:
        """Run every loaded rule against one normalized event dict."""
        hits = []
        for rule in self.rules.values():
            matched_selection = _evaluate_condition(rule.detection, rule.condition, event)
            if matched_selection:
                hits.append(SigmaMatch(
                    rule_id=rule.rule_id, title=rule.title, level=rule.level,
                    tags=rule.tags, matched_selection=matched_selection,
                ))
        return hits

    def stats(self) -> dict:
        return {"loaded_rules": len(self.rules), "yaml_available": YAML_AVAILABLE}


sigma_engine = SigmaEngine()
