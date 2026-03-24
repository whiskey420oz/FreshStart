# Project Overview
FreshStart is a custom SOC/SIEM platform built on a Flask backend and a multi-page SOC dashboard UI. It ingests Wazuh alerts via syslog JSON (UDP 1514), buffers alerts in Redis, processes them asynchronously with a worker, normalizes to a consistent event schema, stores events in SQLite, and serves analytics, investigations, and response workflows through REST APIs and a dashboard UI. Optional OpenSearch indexing is supported for analytics and backfill, and OpenSearch can be used as the primary read source.

# System Architecture
Wazuh Manager -> syslog_output (format=json) -> FreshStart UDP syslog listener -> Redis queue (alerts_queue) -> worker normalization/enrichment -> SQLite events table -> Flask API -> SOC dashboard.

Optional analytics path:
Worker -> OpenSearch (freshstart-events) for searchable analytics and backfill.

Optional enterprise buffering (planned/optional):
Wazuh -> Vector (disk buffer) -> Redis -> worker -> SQLite/OpenSearch.

# Repository Structure
backend/
- app.py: Flask API, routes, and static file serving
- syslog_listener.py: UDP syslog server (pushes to Redis queue)
- alert_store.py: SQLite persistence + analytics queries
- wazuh_client.py: Wazuh API client for auth + active response
- wazuh_health_check.py: standalone health check orchestrator (script)
- config.yaml: local configuration values
- alerts.db: SQLite alert store
- redis_queue/: Redis client package
- workers/alert_worker.py: queue worker to normalize/store alerts
- tools/queue_metrics.py: queue health utility
- tools/push_test_alert.py: queue test utility
- enrichment.py: threat intel enrichment (Geo/ASN/ISP + optional AbuseIPDB/OTX)
- correlation.py: rule-based correlation (bruteforce/port scan/lateral movement)
- mitre_map.py: MITRE mapping fallbacks
- opensearch_client.py: OpenSearch indexing + analytics reads
- api/: staged API namespace (wrappers)
- ingestion/: staged ingestion namespace (wrappers)
- database/: staged data access namespace (wrappers)
- models/: staged schemas namespace (placeholder)
- routes/: staged routing namespace (placeholder)

frontend/
- index.html + dashboard.js + styles.css: main SOC dashboard
- alerts.html + alerts.js: alert management view
- investigations.html + investigations.js: case management UI
- incidents.html + incidents.js: incident queue + workflow
- threat-intel.html + threat-intel.js: IP threat profile lookup
- assets.html + assets.js: asset inventory view (SQLite derived)
- active-response.html + active-response.js: response actions
- settings.html + settings.js: config editing view

docs/
- system_state.md

logs/
- syslog_listener.log, alert_worker.log, flask_app.log

start_freshstart.py, stop_freshstart.py, update_vm_ip.py, requirements.txt

# Implemented Modules
- Log ingestion via syslog JSON (UDP 1514)
- Redis queue buffering (alerts_queue)
- Worker-based normalization + enrichment (Geo/ASN/ISP + optional TI)
- SQLite event storage with alert lifecycle fields
- OpenSearch indexing of normalized events (optional analytics)
- REST API for alerts, analytics, incidents, assets, threat intel
- Dashboard UI (metrics, charts, map, timeline, incident KPIs)
- Alerts management UI (filtering, details, status, create incident)
- Investigations UI (case creation, timeline, notes)
- Incidents workflow (create, assign, investigate, resolve)
- Assets inventory (event-derived + managed assets CRUD)
- Active response UI + backend invocation
- Settings UI + YAML persistence
- Startup automation (start/stop scripts + logs) and IP update tool

# Partially Implemented Modules
- Wazuh API integration (manager + agents + vulnerabilities + FIM endpoints; environment dependent)
- System health monitoring (script exists; partial UI wiring)
- SSE live stream (Redis pub/sub wired; still limited to current alert payload)
- Threat intel enrichment (optional keys for AbuseIPDB/OTX)

# Missing Core Features
- Authentication / access control (no login, RBAC, or API auth)
- Detection rule management UI
- Analyst identity + session management
- Retention and archival policies
- Multi-tenant or role-based views
- Enterprise buffering (Vector/Kafka) not yet deployed

# Integration Status
- Wazuh Manager: integrated via syslog JSON output
- Wazuh API: integrated for manager/agents + response; endpoint availability varies by module
- OpenSearch cluster: indexed by worker; optional read source for analytics
- External APIs: GeoIP (ip-api.com), optional AbuseIPDB/OTX
- Redis: required for ingestion buffering

# Data Flow
1) Wazuh manager sends JSON alerts via syslog (UDP 1514).
2) syslog_listener.py extracts JSON and enqueues to Redis (alerts_queue).
3) workers/alert_worker.py consumes, normalizes, enriches, and inserts into SQLite (events).
4) Worker optionally indexes the normalized event into OpenSearch (freshstart-events).
5) Flask API serves alerts/analytics from SQLite or OpenSearch (PRIMARY_STORAGE).
6) Frontend fetches REST endpoints and live stream from Redis pub/sub.

# Known Issues
- API authentication and RBAC not implemented.
- Wazuh module endpoints (vulnerability/FIM) may return 404/405 if disabled.
- OpenSearch read mode requires correct index mapping and credentials.
- External TI enrichment requires API keys and stable outbound access.

# Next Development Priorities
1) Enterprise buffering: Vector with disk spool -> Redis.
2) Authentication and role-based access controls.
3) Wazuh API module health detection and UX messaging.
4) Retention/archival policies + cold storage.
5) Analyst identity + assignment workflows.
