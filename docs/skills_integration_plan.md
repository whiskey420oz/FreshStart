# Skills Integration Plan (Enterprise SOC)

This plan maps installed agent skills to FreshStart SOC workflows. Use it to pull the right skill at the right phase of development.

## Testing & Quality
Use these before merges or releases to keep behavior stable.
- `webapp-testing`: E2E UI tests (login, alerts stream, dashboards, investigations).
- `playwright`: Browser-level regression testing.
- `gh-fix-ci`: Fix broken CI/test pipelines.

Suggested checks:
- Login flow, alert list load, SSE stream, dashboard metrics, incidents page.

## Security & Auth Hardening
Use for secure SOC platform posture.
- `security-best-practices`: Baseline secure coding, auth, session handling.
- `security-threat-model`: Threat modeling for auth, API, ingestion pipeline.
- `security-architecture-overview`: Architecture-level risk review.
- `security-ownership-map`: Ownership boundaries for subsystems.

Suggested focus:
- Token handling, RBAC (admin/analyst), API protection, audit logging.

## Architecture & Performance
Use to mature the pipeline to enterprise-grade.
- `design-system-patterns`: System consistency and component architecture.
- `interface-design`: IA and interaction consistency.
- `scanning-tools`: Asset + pipeline validation tooling.
- `sentry`: Observability, error tracking strategy.

Suggested focus:
- Redis queue health, worker throughput, backfill safety, OpenSearch reliability.

## Documentation & Project Management
Use to make the system portfolio-ready.
- `doc`: System overview + user manual structure.
- `documentation-templates`: Reusable docs templates.
- `markdown-documentation`: Consistent doc authoring.
- `pdf`: PDF export for reports.

Suggested outputs:
- System architecture doc, user guide, troubleshooting runbook.

## Design & UX
Use to keep the UI enterprise-grade.
- `frontend-design`: UI system upgrades and polish.
- `figma` / `figma-implement-design`: Design handoff and fidelity.
- `tailwind-design-system`: Consistent tokenization.

Suggested focus:
- SIEM command center layout, incident workflow UI, alert detail drawers.

## DevOps & Deployment
Use for shipping/hosting.
- `vercel-deploy`, `netlify-deploy`, `render-deploy`, `cloudflare-deploy`

Suggested focus:
- Frontend hosting and edge optimizations.

## Media & Utilities (Optional)
Use when needed for collateral, demos, or analysis.
- `imagegen`, `sora`, `speech`, `transcribe`, `jupyter-notebook`, `spreadsheet`

Suggested focus:
- Demo assets, report visuals, training materials.

## Recommended Order of Use
1. Security (auth, RBAC, audit logging)
2. Testing (E2E + regression)
3. Architecture/performance (queue stability, storage)
4. UX polish (analyst workflow)
5. Documentation (user + system)

