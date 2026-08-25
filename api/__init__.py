"""External REST API layer (/api/v1) for integrations and third-party tools."""
from .router import api_router
__all__ = ["api_router"]
