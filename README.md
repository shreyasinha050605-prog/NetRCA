# NetRCA AI

AI-assisted Network Root Cause Analysis dashboard with a FastAPI backend and React + Vite frontend.

NetRCA ingests network/security logs, correlates incidents, generates structured RCA reports, and visualizes causal chains and timeline evidence for SOC-style investigation workflows.

## Highlights

- Live incident feed with severity scoring and status tracking.
- AI RCA workflow with structured output (root cause, confidence, impact, remediation).
- Graph-based RCA visualization for causal relationships.
- Security-focused ingestion controls:
  - AES-GCM encryption for stored log payloads.
  - SHA-512 integrity hashing.
  - Optional HMAC-SHA512 verification on ingestion requests.
- Demo scenario seeding for fast local testing (`mixed`, `firewall_misconfig`, `ddos_attack`, `routing_failure`).

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, SQLite
- **Frontend:** React, Vite, Recharts, Lucide
- **Runtime:** Python 3.14, Node.js + npm

## Project Structure

```text
NetRCA/
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── services/
│   └── utils/
└── frontend/
    ├── src/
    ├── package.json
    └── vite.config.js
```

## Quick Start

### 1) Backend

From project root:

```bash
cd backend
.venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

If you do not already have dependencies installed in `.venv`, create/install first:

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install fastapi uvicorn sqlalchemy pydantic openai networkx
```

### 2) Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open the URL shown by Vite (typically `http://127.0.0.1:5173`, or next free port if occupied).

## API Surface (Core)

- `GET /api/incidents` - list current incidents with correlated data and RCA fields.
- `GET /api/metrics` - dashboard metrics (risk score, active alarms, trend points).
- `GET /api/security/posture` - cryptography and transport posture details.
- `POST /api/seed?scenario=<name>` - seed demo logs and generate/update incidents.
- `POST /api/analyze/{incident_ref}` - trigger RCA for an incident.

## Typical Workflow

1. Start backend and frontend.
2. Seed demo logs from the dashboard.
3. Review live incidents and status.
4. Trigger RCA on an incident.
5. Inspect:
   - structured AI report,
   - correlated timeline,
   - graph-based causal chain,
   - audit/security evidence.

## Security Notes

- The backend exposes helper endpoints intended for local/demo usage.
- For production use, restrict CORS, enforce HTTPS/TLS, and enable strict HMAC validation policies.
- Run Uvicorn with SSL cert/key and deploy behind a hardened reverse proxy.

## Troubleshooting

- **`Internal Server Error` when seeding/analyzing:** ensure only one backend process is bound to `8000`.
- **Frontend switches to another port:** `5173` is occupied; use the printed fallback URL.
- **macOS blocks local binaries (`Operation not permitted` / code signature):** remove quarantine attributes if the project was copied from external sources:

  ```bash
  xattr -dr com.apple.quarantine backend frontend
  ```

## License

Add your preferred license (MIT/Apache-2.0/etc.) before public distribution.
