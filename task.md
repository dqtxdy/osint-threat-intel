# CTI Dashboard Cleanup Tasks

- `[x]` Update source coverage backend analytics in `source_coverage.py`
- `[x]` Update entity detail endpoint in backend `api/main.py`
- `[x]` Update typescript types in `types.ts`
- `[x]` Restructure frontend pages into 4 main navigation tabs in `App.tsx`
- `[x]` Create floating chat widget in `App.tsx`
- `[x]` Implement SVG pan/zoom/reset controls and interaction in `App.tsx`
- `[x]` Create EnrichmentSummary component and card views in `App.tsx`
- `[x]` Verify changes: run python backend tests and build the React app

## Final UX Polish Pass
- `[x]` Fix EPSS "EXPLOTT" typo in `App.tsx`
- `[x]` Remove contradictory "Maintain current source mix" recommendation when watch items are present in `source_coverage.py`
- `[x]` Adjust source coverage concentration threshold to > 50% for watch items and keep strengths wording honest ("Strong structured feed reliability" instead of "Balanced") in `source_coverage.py`
- `[x]` Use unified pointer events and SVG screen CTM inverse transformation for robust zoom/pan in `App.tsx`
- `[x]` Suppress node/edge click selections when dragging has moved more than 4px in `App.tsx`
- `[x]` Reset zoom/pan only when focused entity changes instead of any filter or lens change in `App.tsx`
- `[x]` Rename "Reset" to "Fit View" in `App.tsx`
- `[x]` Update and run tests/test_source_coverage.py and verify all test results pass
- `[x]` Verify frontend build is green
