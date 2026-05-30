# QA Report: CTI Analyst Chat Feature Presentation Readiness

This report summarizes the QA verification of the CTI Analyst Chat feature, covering checklist evaluation, demo questions, and implemented fixes to ensure production readiness.

---

## 1. Checklist Evaluation

| Check | Criteria | Status | Details |
|---|---|---|---|
| **1** | Does the chatbot answer using real database context? | **PASSED** | Verified context extraction from the local SQLite database (`data/cti.sqlite3`) using keyword and entity queries. |
| **2** | Does it cite document IDs, source names, and URLs? | **PASSED** | Answers include standard brackets referencing document IDs and sources (e.g., `[Document 628 (CISA KEV)]`). Citations are parsed and displayed as actionable links on the sidebar. |
| **3** | Does it avoid hallucinating when data is missing? | **PASSED** | If context data is absent, the model explicitly acknowledges the lack of information (e.g., when asked about phishing activity summaries). |
| **4** | Does it refuse or redirect offensive exploit requests? | **PASSED** | Attempts to request functional exploit scripts (e.g., Python exploits) are blocked by the system prompt instruction. It redirects the user to defensive steps. |
| **5** | Does the frontend look polished in the light theme? | **PASSED** | Utilizes an elegant light theme color scheme. A minor styling issue where the Send button used an invalid Tailwind CSS class was identified and corrected. |
| **6** | Does the Chat page work when the backend LLM is configured? | **PASSED** | Works seamlessly. Robust JSON sanitization was implemented on the backend to prevent parsing failures caused by markdown code fence blocks or trailing characters returned by the model. |
| **7** | Does it show a clear error when the LLM is not configured? | **PASSED** | Shows a clear alert banner indicating that LLM Chat is disabled, referencing the required `.env` variables, and disabling the input box. |
| **8** | Do tests pass? | **PASSED** | All 25 backend tests (including API, Chat, retrieval, and citation filtering) execute and pass successfully. |
| **9** | Does npm run build pass? | **PASSED** | The frontend production compilation completes cleanly without errors. |

---

## 2. Demo Questions Testing

### Q1: What are our top 5 critical threats?
*   **Result**: **Passed**.
*   **Response Summary**: Identified five critical threats (priority score 100) including:
    1.  `CVE-2024-3400` (Palo Alto GlobalProtect Command Injection)
    2.  `CVE-2025-20333` (Cisco Secure Firewall ASA & FTD RCE)
    3.  `CVE-2025-55182` (Meta React Server Components Deserialization RCE)
    4.  `CVE-2026-48027` (Nx Console Supply Chain Compromise)
    5.  `CVE-2026-9082` (Drupal Core SQL Injection)
*   **Citations**: Cited CISA KEV catalogs, Reddit community channels, JPCERT/CC, and Google Threat Intel documents correctly.

### Q2: Summarize current phishing activity.
*   **Result**: **Passed**.
*   **Response Summary**: Retrieves concrete PhishTank evidence first, using current verified active phishing documents before broader vendor/news context.

### Q3: Why is CVE-2024-3400 important?
*   **Result**: **Passed**.
*   **Response Summary**: Detailed the command injection vulnerability in PAN-OS GlobalProtect gateways and portals, explaining that it allows unauthenticated remote attackers to execute arbitrary code with root privileges. Cited active exploitation in the wild.
*   **Fix Applied**: Resolved a flake where the LLM generated invalid trailing characters that broke Pydantic parsing. Cleaned and sanitized the JSON output string before loading.

### Q4: What languages do our sources cover?
*   **Result**: **Passed**.
*   **Response Summary**: Stated that 4 languages are covered: English (`en`), French (`fr`), Japanese (`ja`), and Dutch (`nl`) based on metadata across 23 sources and 2,790 documents.

### Q5: Which sources are weakest or unavailable?
*   **Result**: **Passed**.
*   **Response Summary**: Identified "community" reliability sources (such as Reddit `r/cybersecurity`, `r/netsec`, `r/blueteamsec`, `r/threatintel`, and `r/Malware`) and "medium" reliability sources (e.g. `The Hacker News`, `BleepingComputer`, `SecurityWeek`, and `KrebsOnSecurity`) as the weaker tiers. Noted that the "gaps" field was empty.

### Q6: Explain the strongest evidence for malware activity.
*   **Result**: **Passed**.
*   **Response Summary**: Covered three primary areas:
    1.  UNC6201 zero-day exploitation of Dell RecoverPoint to deploy `BRICKSTORM` and `GRIMBOLT` malware in vSphere environments.
    2.  UNC6692 Helpdesk social engineering campaigns deploying a custom modular malware suite.
    3.  Supply chain compromises added to CISA's KEV Catalog (e.g., `Daemon Tools Lite` and `Nx Console` malicious extensions).

---

## 3. Implemented Fixes and Polish

We made two improvements directly inside the workspace to improve stability and styling:

### 1. Robust JSON Parsing and Sanitization
*   **Files Modified**: 
    *   [chat.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/llm/chat.py#L72)
    *   [reporting.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/llm/reporting.py#L122)
*   **Bug**: If the LLM wraps its response in markdown code blocks (e.g. ````json ... ````) or appends trailing characters (like a stray bracket or brace), Pydantic's `model_validate_json` would crash with a validation error.
*   **Fix**: Added a string cleanup helper that strips markdown wrapper blocks, identifies the actual JSON structure bounding braces `{` and `}`, and passes the clean payload to validation.

### 2. Submit Button Hover Color
*   **File Modified**: 
    *   [App.tsx](file:///home/respectthanh/Workspace/vsc/pentest_project/frontend/src/App.tsx#L1710)
*   **Bug**: The chat input Send button declared an invalid class `hover:sky-300` (missing the color target type prefix `bg-`). In the light theme, this resulted in no hover color change or poor contrast.
*   **Fix**: Changed the class to a valid Tailwind declaration `hover:bg-sky-700` which provides a smooth hover color matching the deep blue style.

### 3. Retrieval and Citation Hardening
*   **Files Modified**:
    *   [retrieval.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/chat/retrieval.py)
    *   [chat.py](file:///home/respectthanh/Workspace/vsc/pentest_project/cti_pipeline/llm/chat.py)
    *   [test_chat.py](file:///home/respectthanh/Workspace/vsc/pentest_project/tests/test_chat.py)
*   **Bug**: Category terms such as `phishing` and `malware` could be under-weighted, causing generic vendor reports to outrank concrete threat-feed evidence.
*   **Fix**: Added intent-aware retrieval weighting so phishing questions prioritize PhishTank and malware/IOC questions prioritize ThreatFox and URLhaus. Chat citations are now filtered against retrieved context so invented document links cannot appear in the sidebar.
