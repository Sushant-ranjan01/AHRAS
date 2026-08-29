import time, uuid
from starlette.middleware.base import BaseHTTPMiddleware
from .metrics import REQUESTS, LATENCY

class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.perf_counter()
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            raise
        path = request.url.path
        LATENCY.labels(request.method, path).observe(time.perf_counter() - start)
        REQUESTS.labels(request.method, path, str(response.status_code)).inc()
        response.headers["X-Request-ID"] = request_id
        return response
