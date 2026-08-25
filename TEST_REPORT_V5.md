# AHRAS v5 — Test Report Addendum

**Generated**: Automated pytest run, this session
**Result**: ✅ 158/158 PASSED — 0 FAILED — 0 ERRORS
**Python**: 3.12.3 · **pytest**: 9.1.1

This builds on `TEST_REPORT.md` (v4, 84 tests) and `TEST_REPORT_PHASE2.md`
(124 tests after Phase 2). The v5 risk-engine and risk-explainer rewrite
described in `ARCHITECTURE.md`'s "v5 Architecture Review" section did not
require any test changes — the existing `tests/test_risk_engine.py` and
`tests/test_risk_explainer.py` suites (18 tests) pass unmodified against
both the new `risk_engine/risk_scorer.py` (v5.0 multi-signal fusion +
historical recidivism boost) and the rewritten `risk_explainer/explainer.py`
(faithful-by-construction reconstruction from `raw_components`).

New in this pass: `evaluation/research_experiments.py`, covering the
ablation study and three validation experiments referenced in
`IEEE_PAPER_DRAFT.md` Section VI-D through VI-G (see that section and
`RESEARCH.md` for details and reproduction commands). This module is a
standalone evaluation script, not exercised by the pytest suite, since its
job is to produce research-validation numbers rather than to assert
pass/fail behavior.

```
$ python -m pytest tests/ -q
158 passed in 1.84s
```
