# FreshStart SOC Platform

FreshStart is a custom SIEM/SOC platform with a Flask backend and multi-page SOC dashboard UI. It ingests Wazuh alerts via syslog JSON output (UDP 1514), normalizes/enriches them, stores alerts in SQLite, and serves real-time analytics, correlation, and investigation workflows through the dashboard.

## Architecture

Wazuh Manager -> syslog_output (format=json) -> FreshStart UDP syslog listener -> Redis queue -> alert worker (normalize + enrich + correlate) -> SQLite events -> Flask API -> SOC dashboard (SSE + REST)

Optional historical backfill:
OpenSearch (wazuh-alerts-*) -> backfill thread -> SQLite events

Optional enterprise buffering:
Wazuh -> Vector (disk buffer) -> Redis -> worker -> SQLite/OpenSearch

## Project Structure

```text
backend/
  app.py
  syslog_listener.py
  alert_store.py
  correlation.py
  enrichment.py
  mitre_map.py
  api/
  ingestion/
  database/
  models/
  routes/
  integrations/
    wazuh_client.py
  redis_queue/
    redis_client.py
  workers/
    alert_worker.py
  tools/
    queue_metrics.py
    push_test_alert.py
    push_bruteforce_test.py
    push_ssh_flood.py
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
  incidents.html
  incidents.js
  assets.html
  assets.js
  active-response.html
  active-response.js
  threat-intel.html
  threat-intel.js
  settings.html
  settings.js

docs/
  system_state.md
  vector_buffering.md
  vector_service.md

vector/
  vector.toml

requirements.txt
start_freshstart.py
stop_freshstart.py
update_vm_ip.py
```

## Running FreshStart

```bash
pip install -r requirements.txt
python start_freshstart.py
```

Open `http://localhost:5000`.

## Syslog Listener

- Listens on UDP/TCP `0.0.0.0:1514`
- Parses JSON alerts and pushes them into Redis
- Worker normalizes + enriches + correlates alerts, then stores into SQLite
- Dashboard receives real-time updates via SSE

## API (Selected)

- `GET /alerts`: Recent alerts with pagination and time filters
- `GET /metrics`, `GET /metrics/soc`: SOC metrics
- `GET /top_attackers`, `/rule_statistics`, `/alerts_over_time`, `/risky_hosts`
- `GET /api/assets`: Assets derived from SQLite events
- `GET /api/incidents`: Correlated incidents
- `POST /api/incidents/from-alert`: Create incident from an alert
- `GET /api/attackers`: Attacker profiling
- `GET /api/risk-scores`: Host risk scoring
- `GET /api/mitre-stats`: MITRE ATT&CK coverage
- `GET /api/attack-map`: Attack map aggregation
- `GET /api/threat-intel?ip=...`: Threat intel profile for IP
- `POST /api/response/block-ip`: Trigger Wazuh active response
- `GET/POST /api/settings`: Read/write configuration
- `GET /alerts/stream`: SSE live alert stream

## Notes

- UDP 1514 does not require elevated privileges, unlike 514.
- Wazuh API is used for manager/agents visibility and active response.
- OpenSearch backfill is optional and can be enabled via `config.yaml`.
- Vector buffering can be used for offline-safe ingestion. See `docs/vector_buffering.md`.
- Vector autostart instructions are in `docs/vector_service.md`.

## Updating VM IP

If your Wazuh/Redis/OpenSearch VM IP changes, run:

```bash
python update_vm_ip.py
```

This updates `backend/config.yaml` and prints the changes.

## Troubleshooting

### Agent shows disconnected after VM IP change

If the Wazuh Manager VM IP changes, the Windows agent must be updated to point to the new manager IP.

1. Edit the agent config on the Windows machine:

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Update the `<server>` block:

```xml
<server>
  <address>192.168.33.101</address>
  <port>1514</port>
  <protocol>udp</protocol>
</server>
```

2. Restart the agent service (PowerShell as Administrator):

```powershell
net stop wazuh
net start wazuh
```

3. Verify on the VM:

```bash
sudo /var/ossec/bin/agent_control -lc
```

The agent should show as **Active**.

### Wazuh API auth check (TOKEN workflow)

Use this when Wazuh API calls return timeouts or 401 errors.

On the VM:

```bash
TOKEN=$(curl -k -u wazuh:wazuh "https://localhost:55000/security/user/authenticate?raw=true")
curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:55000/manager/info"
```

If the second command returns manager info, the API is healthy and credentials are correct.

### OpenSearch auth check (basic auth)

OpenSearch does not use the Wazuh API token. It uses basic auth credentials:

```bash
curl -k -u admin:YOUR_PASSWORD https://localhost:9200
```

If you see cluster JSON, update `backend/config.yaml` with the same user/password.
