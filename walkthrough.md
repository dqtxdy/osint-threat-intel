# Walkthrough - CTI Analyst Chat Implementation

We have successfully implemented the CTI Analyst Chat feature, allowing analysts to query threat intelligence context from the local SQLite database via a retrieval-augmented LLM interface.

## Changes Made

### 1. Backend Chat Retrieval Module
- Created [retrieval.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/chat/retrieval.py).
- Extracted security entities (CVE, IP, domain, hash, ATT&CK technique) from questions.
- Implemented simple but effective keyword and entity lookup against documents, entities, and sources.
- Structured retrieval context returning priority findings, source mix, trends, and matching documents (with 1200-character compact body excerpts).

### 2. Backend Chat LLM Module
- Created [chat.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/llm/chat.py).
- Defined structured request and response formats via Pydantic (`ChatCitation`, `ChatRelatedEntity`, `ChatResponse`).
- Implemented a conversational interface that passes the retrieved context as system instructions.
- Guided the assistant to operate as a defensive CTI analyst (cites evidence, lists caveats, includes follow-ups, handles weak evidence, and avoids offensive exploitation steps).

### 3. FastAPI Endpoint
- Modified [main.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/api/main.py) to add `POST /api/chat`.
- Validated request structure and handled clean errors (HTTP 400 for disabled/unconfigured LLM, HTTP 500 for internal errors).

### 4. Frontend Client Update
- Added the `chat` method to `api` in [api.ts](file:///home/respectthanh/Workspace/vsc/pentest_project/frontend/src/api.ts).

### 5. Frontend UI Page
- Added the `"chat"` view and navigation item in [App.tsx](file:///home/respectthanh/Workspace/vsc/pentest_project/frontend/src/App.tsx).
- Implemented a rich two-column layout:
  - Left column: Chat window and transcript.
  - Right column: Quick suggested analyst queries, citations, caveats, and related entities.
  - LLM configuration warning banner when environment values are missing.

---

## Verification Results

### 1. Automated Tests
We added 3 comprehensive tests in [test_chat.py](file:///home/respectthanh/Workspace/vsc/pentest_project/tests/test_chat.py) and ran `pytest`. All 24 tests passed successfully:
```bash
python3 -m pytest tests
============================== 24 passed in 8.03s ==============================
```

### 2. Frontend Production Build
We verified that the React/TypeScript bundle builds successfully without compilation errors:
```bash
npm run build
dist/index.html                   0.41 kB │ gzip:   0.27 kB
dist/assets/index-kMxtvUla.css   17.51 kB │ gzip:   4.54 kB
dist/assets/index-BlRPoG7G.js   614.36 kB │ gzip: 180.77 kB
✓ built in 1.05s
```
