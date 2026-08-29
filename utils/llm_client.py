"""
AHRAS — Shared Local LLM Client
════════════════════════════════════════════════════════════════════════════
Single place that talks to a local Ollama (or any OpenAI-/Ollama-compatible
`/api/generate`) endpoint. Both soar/copilot.py and security_intelligence's
Local Security AI layer call through here so there's exactly one code path
to configure, test, and point at a real model.

Configuration (env vars — all optional, feature degrades gracefully if unset):
  AHRAS_LOCAL_LLM_URL      e.g. http://localhost:11434/api/generate
  AHRAS_LOCAL_LLM_MODEL    e.g. llama3   (default: llama3)
  AHRAS_LOCAL_LLM_TIMEOUT  seconds       (default: 8)

If AHRAS_LOCAL_LLM_URL is not set, every call returns None immediately and
callers fall back to their deterministic templates — nothing ever crashes
or blocks because Ollama isn't running.
"""
import logging
import os
from typing import Optional

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

logger = logging.getLogger("ahras.llm_client")

LOCAL_LLM_URL = os.environ.get("AHRAS_LOCAL_LLM_URL", "")
LOCAL_LLM_MODEL = os.environ.get("AHRAS_LOCAL_LLM_MODEL", "llama3")
LLM_TIMEOUT_SECS = float(os.environ.get("AHRAS_LOCAL_LLM_TIMEOUT", "8"))


def is_llm_configured() -> bool:
    return bool(LOCAL_LLM_URL) and REQUESTS_OK


def model_name() -> str:
    return LOCAL_LLM_MODEL


def call_local_llm(prompt: str, system: Optional[str] = None) -> Optional[str]:
    """
    Calls the configured local LLM's /api/generate endpoint (Ollama-shaped
    request/response). Returns the raw text response, or None if the LLM
    isn't configured, isn't reachable, or errors out — callers must always
    have a deterministic fallback for the None case.
    """
    if not LOCAL_LLM_URL or not REQUESTS_OK:
        return None
    try:
        payload = {"model": LOCAL_LLM_MODEL, "prompt": prompt, "stream": False}
        if system:
            payload["system"] = system
        resp = requests.post(LOCAL_LLM_URL, json=payload, timeout=LLM_TIMEOUT_SECS)
        if resp.status_code != 200:
            logger.warning("Local LLM returned %s, falling back", resp.status_code)
            return None
        data = resp.json()
        return (data.get("response") or "").strip() or None
    except Exception as exc:
        logger.info("Local LLM unreachable (%s) — using fallback", exc)
        return None
