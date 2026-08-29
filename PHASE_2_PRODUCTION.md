# AHRAS Phase 2 — Production Infrastructure

This phase productionizes the platform without changing the existing detection, XAI, SOAR, RBAC, or adaptive-learning modules.

## Delivered

- Dedicated production Docker image with non-root execution and Tini.
- Production Docker Compose with isolated frontend/backend networks.
- MongoDB is not published to the host.
- MongoDB health checks and persistent data/config volumes.
- AHRAS application health check and resource limits.
- Nginx TLS termination, HTTP-to-HTTPS redirect, security headers, request limiting, and connection limiting.
- On-demand MongoDB backup and restore helpers with retention of the newest 14 backups.
- Production environment template with secret placeholders.
- Fail-fast production startup validation.
- CI security pipeline for syntax, tests, linting, formatting, Bandit, and dependency auditing.
- `.dockerignore` to prevent secrets, caches, datasets, and runtime files entering the image.

## Operational notes

TLS certificates are intentionally not committed. Put `fullchain.pem` and `privkey.pem` under `nginx/ssl/` on the deployment host. For a serious deployment, keep backups off-host and use a managed secret store.
