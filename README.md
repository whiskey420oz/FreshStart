# FreshStart SOC Platform

FreshStart is a custom SIEM platform with a Flask backend and multi-page SOC dashboard UI. It ingests Wazuh alerts via syslog JSON output (UDP 1514), normalizes them, stores alerts in SQLite, and serves real-time analytics and investigation workflows through the dashboard.

## Architecture

Wazuh Manager → syslog_output (format=json) → FreshStart UDP syslog listener → normalization → SQLite alerts table + in-memory cache → Flask API → SOC dashboard (SSE + REST)

## Project Structure

```text
backend/
  app.py
  syslog_listener.py
  alert_store.py
  wazuh_client.py
  wazuh_health_check.py
  config.yaml
  alerts.db

frontend/
  index.html
  dashboard.js
  styles.css
  alerts.html
  alerts.js
  investigations.html
  investigations.js
  assets.html
  assets.js
  active-response.html
  active-response.js
  settings.html
  settings.js

docs/
  system_state.md

requirements.txt
```

## Running FreshStart

```bash
pip install -r requirements.txt
python backend/app.py
```

Open `http://localhost:5000`.

## Syslog Listener

- Listens on UDP `0.0.0.0:1514`
- Parses JSON alerts and stores them in SQLite
- Provides real-time updates via SSE

## API (Selected)

- `GET /alerts`: Recent alerts with pagination and time filters
- `GET /metrics`: Aggregate alert metrics
- `GET /top_attackers`, `/rule_statistics`, `/alerts_over_time`, `/risky_hosts`
- `GET /api/assets`: Assets derived from SQLite alerts
- `POST /api/response/block-ip`: Trigger Wazuh active response
- `GET/POST /api/settings`: Read/write configuration
- `GET /stream`: SSE live alert stream

## Notes

- UDP 1514 does not require elevated privileges, unlike 514.
- Wazuh API is used only for active response in the current build.
- OpenSearch is not integrated for alert indexing.
