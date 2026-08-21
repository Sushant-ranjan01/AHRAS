"""Rule/signature-based detection for known attack patterns."""
from .engine import SignatureEngine, SignatureResult
__all__ = ["SignatureEngine", "SignatureResult"]
