#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 -m cti_pipeline.cli run-pipeline --source all --days 3650
python3 -m cti_pipeline.cli prioritize --days 3650 --limit 5
python3 -m cti_pipeline.cli trends --days 3650 --limit 10

cat <<'MSG'

Demo data is ready.
Open the dashboard with:

  python3 -m streamlit run dashboard/app.py

Recommended demo flow:
1. Threat Feed
2. Priorities
3. Trends
4. Entity Explorer
5. Report
MSG
