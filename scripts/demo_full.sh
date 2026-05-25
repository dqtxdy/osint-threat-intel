#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 -m cti_pipeline.cli run-pipeline --source all --days 3650 --fresh --live-only --enrich-limit 8

cat <<'MSG'

Start the API in terminal 1:

  python3 -m uvicorn cti_pipeline.api.main:app --host 127.0.0.1 --port 8000 --reload

Start the React dashboard in terminal 2:

  cd frontend
  npm run dev

Open:

  http://127.0.0.1:5173

Recommended demo flow:
1. Mission Control
2. OSINT Coverage
3. Priority Queue
4. Threat Feed
5. Entity Workbench
6. Knowledge Graph
7. Reports
8. Exports
MSG
