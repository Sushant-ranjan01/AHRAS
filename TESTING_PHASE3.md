# AHRAS Phase 3 — Quality & Testing

Phase 3 makes AHRAS easier to change safely by adding a repeatable quality gate around authentication, RBAC, token lifecycle, API route protection, and detection performance.

## Local quality gate

```bash
python -m compileall -q .
ruff check .
black --check .
mypy auth api security rbac database detection risk_engine risk_explainer xai observability
pytest -q --cov=. --cov-report=term-missing --cov-report=html
bandit -r . -x ./venv,./.venv,./tests -ll
pip-audit -r requirements.txt
```

## Performance gate

Performance tests are intentionally opt-in so normal CI remains deterministic:

```bash
AHRAS_RUN_PERF=1 pytest -m performance -q
```

The performance test is a regression guard, not a production SLA. It measures the in-process risk engine without network or database I/O.

## Test categories

- `unit` — isolated module tests
- `security` — auth, RBAC, token and route protection
- `integration` — multiple AHRAS modules working together
- `performance` — opt-in latency regression checks

Run one category:

```bash
pytest -m security -q
pytest -m integration -q
```

## Coverage policy

Coverage is measured with branch coverage. New functionality should add tests for both successful and failure paths, especially authorization failures and malformed input.
