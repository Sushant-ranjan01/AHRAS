# AHRAS Phase 6 — ML/AI Operations

Phase 6 operationalizes the existing anomaly/risk intelligence rather than adding another model.

## Included
- Immutable local model artifact registry with SHA-256 checksums.
- Automatic registration after successful `retrain_baseline.py train`.
- Active model metadata and promotion endpoint.
- Analyst feedback store (`data/ml_feedback.jsonl`).
- Feedback bridge into the existing adaptive risk-weight learner when cached risk evidence is available.
- Feature drift detection using Population Stability Index (PSI).
- Persisted drift snapshots and `/api/v1/ml/drift`.
- Offline evaluator for labelled `.npy` datasets.
- ML lifecycle APIs: `/api/v1/ml/status`, `/api/v1/ml/models`, `/api/v1/ml/register`, `/api/v1/ml/promote/{version}`, `/api/v1/ml/feedback`.

## Safe operating model
1. Train on a clean baseline.
2. Register the resulting artifact automatically.
3. Evaluate against a labelled holdout before promotion.
4. Record analyst true/false-positive feedback.
5. Monitor PSI drift; retrain when drift is sustained and validated.
6. Promote only an approved registry version.

The registry does not automatically promote a new model. This is intentional: model deployment remains a controlled SOC/admin action.
