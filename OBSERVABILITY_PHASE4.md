# AHRAS Phase 4 — Observability & SOC Monitoring

## Added
- JSON structured logs with UTC timestamps, logger, service and request IDs
- `/health/live` liveness endpoint
- `/health/ready` readiness endpoint with MongoDB and worker state
- `/health` operational status with queues and worker health
- Prometheus metrics for requests, latency, workers, queues, CPU, memory and MongoDB
- Worker heartbeat/error tracking
- Request correlation via `X-Request-ID`

## Metrics
`/metrics` exposes Prometheus-compatible metrics including:
- `ahras_api_requests_total`
- `ahras_api_request_latency_seconds`
- `ahras_worker_health`
- `ahras_worker_errors_total`
- `ahras_queue_depth`
- `ahras_process_cpu_percent`
- `ahras_process_memory_bytes`
- `ahras_mongodb_up`

## Operations
Use `/health/live` for container liveness and `/health/ready` for load-balancer readiness. A 503 readiness response means MongoDB or a registered worker is not healthy.
