# test_framework_mapper.py
# Tests for governance/framework_mapper.py. Offline, no API key.
#
# Author: Omonivie Cynthia Jatto

import json

from governance.framework_mapper import map_findings, build_summary, FRAMEWORK_MAP


def _fake_report():
    return {
        "module": "Prompt Injection Tester (LLM01)",
        "results": [
            {
                "id": "PI-002",
                "category": "direct_override",
                "description": "Role reassignment attack",
                "status": "VULNERABLE",
                "severity": "MEDIUM",
            },
            {
                "id": "PI-001",
                "category": "direct_override",
                "description": "Direct instruction override",
                "status": "SAFE",
                "severity": "NONE",
            },
        ],
    }


def test_every_known_category_has_all_three_frameworks():
    for category, frameworks in FRAMEWORK_MAP.items():
        assert {"eu_ai_act", "nist_ai_rmf", "owasp_llm_top_10"}.issubset(frameworks.keys())


def test_map_findings_skips_safe_results():
    findings = map_findings([_fake_report()])
    assert len(findings) == 1
    assert findings[0]["id"] == "PI-002"


def test_map_findings_attaches_framework_references():
    findings = map_findings([_fake_report()])
    assert findings[0]["frameworks"]["owasp_llm_top_10"] == "LLM01:2025 Prompt Injection"


def test_map_findings_handles_unknown_category_gracefully():
    report = {
        "module": "test",
        "results": [{"id": "X-1", "category": "made_up_category", "status": "VULNERABLE", "severity": "LOW"}],
    }
    findings = map_findings([report])
    assert findings[0]["frameworks"]["eu_ai_act"] == "Not mapped -- review manually"


def test_build_summary_counts_severity():
    findings = map_findings([_fake_report()])
    summary = build_summary(findings)
    assert summary["total_findings"] == 1
    assert summary["severity_breakdown"]["MEDIUM"] == 1
