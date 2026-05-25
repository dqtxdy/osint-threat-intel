from cti_pipeline.llm.reporting import LLMAnalystReport, ReportFinding, render_llm_report


def test_renders_llm_report_with_evidence_sources():
    report = LLMAnalystReport(
        executive_summary="Three CVEs appear across structured and social sources.",
        key_findings=[
            ReportFinding(
                title="CVE visibility",
                summary="CVE-2024-3400 is present in the provided evidence.",
                confidence="high",
                evidence_document_ids=[1],
            )
        ],
        priority_entities=["CVE-2024-3400"],
        recommended_actions=["Review affected GlobalProtect systems."],
        caveats=["Social sources require corroboration."],
    )
    context = {
        "documents": [
            {
                "id": 1,
                "source_name": "CISA Known Exploited Vulnerabilities",
                "title": "CVE-2024-3400",
                "url": "https://example.test/cve",
            }
        ]
    }

    markdown = render_llm_report(report, context, days=3650)

    assert "LLM Analyst Report" in markdown
    assert "Document 1" in markdown
    assert "CVE-2024-3400" in markdown

