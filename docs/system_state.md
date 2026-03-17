# Project Overview
FreshStart is a custom SIEM platform built on a Flask backend and multi-page SOC dashboard UI. It ingests Wazuh alerts via syslog JSON (UDP 1514), normalizes them, persists alerts in SQLite, and provides real-time analytics and investigation tooling through REST and SSE.

# System Architecture
Wazuh Manager → syslog_output (format=json) → FreshStart UDP syslog listener → normalization → SQLite alerts table + in-memory cache → Flask API → SOC dashboard (SSE + REST).

# Repository Structure
backend/
- app.py: Flask API, routes, and static file serving
- syslog_listener.py: UDP syslog server and alert normalization
- alert_store.py: SQLite persistence + in-memory analytics cache
- wazuh_client.py: Wazuh API client for auth + active response
- wazuh_health_check.py: standalone health check orchestrator (script)
- config.yaml: local configuration values
- alerts.db: SQLite alert store

frontend/
- index.html + dashboard.js + styles.css: main SOC dashboard
- alerts.html + alerts.js: alert management view
- investigations.html + investigations.js: case management UI
- assets.html + assets.js: asset inventory view (SQLite derived)
- active-response.html + active-response.js: response actions
- settings.html + settings.js: config editing view

docs/
- system_state.md

requirements.txt

# Implemented Modules
- Log ingestion via syslog JSON (UDP 1514)
- Alert normalization and storage in SQLite
- REST API for alerts and analytics
- SSE stream for real-time alert updates
- Dashboard UI (metrics, charts, map, timeline)
- Alerts investigation UI (filtering, details, status)
- Investigations UI (case creation, timeline, notes)
- Assets inventory (derived from SQLite alerts)
- Active response UI + backend invocation
- Settings UI + YAML persistence

# Partially Implemented Modules
- Wazuh API integration (only used for active response; agent inventory not used)
- System health monitoring (script exists, not wired into API/UI)
- Analytics (basic metrics only; no correlation, enrichment, or long-term trends)

# Missing Core Features
- OpenSearch indexing and query integration
- Authentication / access control (no login, RBAC, or API auth)
- Detection rule management
- Alert correlation and enrichment (geo-IP, MITRE, TI feeds)
- Case persistence in backend (currently localStorage only)
- Retention and archival policies
- Multi-tenant or role-based views

# Integration Status
- Wazuh Manager: integrated via syslog JSON output
- Wazuh API: partial (active response only; no alert ingestion)
- OpenSearch cluster: not integrated
- External APIs: none

# Data Flow
1) Wazuh manager sends JSON alerts via syslog (UDP 1514).
2) syslog_listener.py extracts JSON and normalizes fields.
3) alert_store.py writes each alert to SQLite and updates in-memory analytics.
4) Flask API exposes alerts, analytics, assets, and SSE stream endpoints.
5) Frontend fetches REST endpoints and listens to SSE for live updates.

# Known Issues
- README.md was updated, but needs periodic syncing with system changes.
- Wazuh API requires network accessibility; not validated in UI.
- No API authentication; active response endpoint is open.
- Health check script not accessible from UI.

# Next Development Priorities
1) Implement authentication and role-based access controls.
2) Add OpenSearch integration or remove its references and scripts.
3) Persist investigations and alert status in backend storage.
4) Add alert enrichment (geo-IP, threat intel, MITRE).
5) Wire health checks into a `/api/health` endpoint and UI panel.
6) Add retention policies and alert archival.
