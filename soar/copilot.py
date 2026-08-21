"""
AHRAS v4 — LLM Playbook Copilot  (Phase 2 — Research Contribution)
═══════════════════════════════════════════════════════════════════════════
Problem: soar/engine.py runs fixed playbooks (block IP -> case -> report).
That's reliable but mute — an analyst still has to write up what happened
and why, and a non-technical exec still can't read a raw alert JSON.

Solution: a thin, pluggable LLM layer that turns a PlaybookRun + the alert
context that triggered it into:
  1. a natural-language incident response note (for the case file), and
  2. a one-paragraph executive summary (no jargon, for leadership).

Honest scope note: no model weights ship with this project. This module
talks to a *local* OpenAI-compatible / Ollama-compatible endpoint if one
is configured (e.g. `ollama run llama3` or `ollama run mistral` exposed at
http://localhost:11434), so the "LLM SOAR" claim is real once you point it
at an actual local model — nothing is faked. If no LLM endpoint is
reachable (the default in this sandbox, and in most fresh installs), it
falls back to a deterministic template generator built from the same
fields, so the feature never breaks the pipeline and callers don't need
to special-case "LLM unavailable".
"""
import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

logger = logging.getLogger("ahras.soar.copilot")

# Point this at any OpenAI-/Ollama-compatible /api/generate or /v1/chat/completions
# endpoint running a local model (Llama 3, Mistral, etc). Left unset by default.
LOCAL_LLM_URL = os.environ.get("AHRAS_LOCAL_LLM_URL", "")     # e.g. http://localhost:11434/api/generate
LOCAL_LLM_MODEL = os.environ.get("AHRAS_LOCAL_LLM_MODEL", "llama3")
LLM_TIMEOUT_SECS = float(os.environ.get("AHRAS_LOCAL_LLM_TIMEOUT", "8"))


@dataclass
class PlaybookNarrative:
    incident_note: str        # detailed, analyst-facing
    exec_summary: str         # one paragraph, plain language
    generated_by: str         # "local-llm:<model>" or "template"


def _call_local_llm(prompt: str) -> Optional[str]:
    if not LOCAL_LLM_URL or not REQUESTS_OK:
        return None
    try:
        resp = requests.post(
            LOCAL_LLM_URL,
            json={"model": LOCAL_LLM_MODEL, "prompt": prompt, "stream": False},
            timeout=LLM_TIMEOUT_SECS,
        )
        if resp.status_code != 200:
            logger.warning("Local LLM returned %s, falling back to template", resp.status_code)
            return None
        data = resp.json()
        # Ollama-style response; adjust here if pointing at a different server
        return (data.get("response") or "").strip() or None
    except Exception as exc:
        logger.info("Local LLM unreachable (%s) — using template fallback", exc)
        return None


def _template_incident_note(run: dict) -> str:
    actions = ", ".join(run.get("actions_taken", [])) or "no automated actions recorded"
    return (
        f"Playbook '{run.get('playbook','unknown')}' triggered by {run.get('trigger','an alert')} "
        f"originating from {run.get('src_ip','an unknown source')}. "
        f"Automated response: {actions}. "
        f"Outcome: {'succeeded' if run.get('success') else 'FAILED — needs manual review'}. "
        f"Linked case: {run.get('case_id') or 'none created'}."
    )


def _template_exec_summary(run: dict, risk_score: Optional[float] = None) -> str:
    severity = "a high-severity" if (risk_score or 0) >= 70 else "a"
    return (
        f"Our security system automatically detected and responded to {severity} threat "
        f"from {run.get('src_ip','an external source')}. "
        f"{'The threat was contained automatically.' if run.get('success') else 'Automated containment did not fully succeed and a security analyst has been notified to review it manually.'} "
        f"No further action is needed from you at this time."
    )


def generate_narrative(playbook_run: dict, risk_score: Optional[float] = None,
                        extra_context: Optional[dict] = None) -> PlaybookNarrative:
    """
    playbook_run: dict form of soar.engine.PlaybookRun (its .to_dict())
    risk_score:   the risk score (0-100) that triggered this playbook, if known
    extra_context: any extra fields worth mentioning (MITRE technique, asset name, etc)
    """
    ctx = extra_context or {}
    prompt = (
        "You are a SOC analyst assistant. Given this automated security playbook "
        "execution, write (1) a short technical incident note for the case file, and "
        "(2) a one-paragraph plain-language summary for a non-technical executive. "
        "Return strict JSON with keys 'incident_note' and 'exec_summary'.\n\n"
        f"Playbook run: {json.dumps(playbook_run)}\n"
        f"Risk score: {risk_score}\n"
        f"Extra context: {json.dumps(ctx)}\n"
    )

    llm_raw = _call_local_llm(prompt)
    if llm_raw:
        try:
            parsed = json.loads(llm_raw)
            if "incident_note" in parsed and "exec_summary" in parsed:
                return PlaybookNarrative(
                    incident_note=parsed["incident_note"],
                    exec_summary=parsed["exec_summary"],
                    generated_by=f"local-llm:{LOCAL_LLM_MODEL}",
                )
        except (json.JSONDecodeError, TypeError):
            # Model didn't return clean JSON — still better than nothing,
            # use its raw text as the incident note and template the exec summary.
            return PlaybookNarrative(
                incident_note=llm_raw,
                exec_summary=_template_exec_summary(playbook_run, risk_score),
                generated_by=f"local-llm:{LOCAL_LLM_MODEL} (raw)",
            )

    return PlaybookNarrative(
        incident_note=_template_incident_note(playbook_run),
        exec_summary=_template_exec_summary(playbook_run, risk_score),
        generated_by="template",
    )


def is_llm_configured() -> bool:
    return bool(LOCAL_LLM_URL) and REQUESTS_OK
