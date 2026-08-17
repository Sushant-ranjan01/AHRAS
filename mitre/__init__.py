"""Maps detected attack behavior to MITRE ATT&CK technique IDs."""
from .mapper import MitreMapper, MitreResult
__all__ = ["MitreMapper", "MitreResult"]
