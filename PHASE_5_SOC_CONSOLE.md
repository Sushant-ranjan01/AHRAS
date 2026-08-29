# AHRAS Phase 5 — SOC Analyst Command Center

Phase 5 upgrades the existing dashboard into an analyst-oriented investigation workflow.

## Added

- SOC Command Center dashboard available to all authenticated roles.
- Triage queue for open/high/critical alerts.
- Alert investigation drill-down.
- Related event timeline by source/target IP.
- MITRE ATT&CK context on alert investigations.
- Threat-intelligence enrichment from the existing ThreatIntelManager.
- Linked-case discovery.
- Create a case directly from an alert.
- Role-aware containment actions; acknowledgement/resolution remain admin/master gated.
- Recent incident and active-case views.
- Authenticated CSV alert export.
- Responsive SOC workflow UI for desktop/mobile.

## API

- `GET /api/soc/overview`
- `GET /api/soc/alerts/{alert_id}/context`
- `GET /api/soc/timeline/{ip}`
- `GET /api/soc/export/alerts.csv`

## Analyst workflow

`Triage → Investigate → Contain → Case → Close`

The phase intentionally reuses AHRAS's existing alert, case, MITRE, threat-intel, event, and SOAR modules instead of creating parallel data stores.
