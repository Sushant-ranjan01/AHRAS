# AHRAS Security Hardening

## Authentication
- Access JWTs default to 30 minutes.
- Refresh tokens are random, short-lived (7 days by default), single-use and rotated.
- Logout revokes the session so previously issued access tokens stop validating.
- Passwords require 12+ characters, upper/lowercase, a number and a special character.
- Failed logins are locked after five attempts in five minutes by the existing AuthManager.

## API protection
- Login is rate limited separately from general API traffic.
- All API traffic is subject to an IP sliding-window limiter.
- Security headers are added by middleware.
- CORS remains explicit; production must set `ALLOWED_ORIGINS`.

## Audit and observability
Security-sensitive actions are written to the `audit_logs` MongoDB collection when MongoDB is available and are also emitted to application logs. `/metrics` exposes Prometheus metrics.

## Production
Use `docker-compose.prod.yml`. Do not commit `.env`, credentials, certificates, backups, datasets or model artifacts. Set a random `SECRET_KEY`, MongoDB credentials and explicit allowed origins before deployment.
