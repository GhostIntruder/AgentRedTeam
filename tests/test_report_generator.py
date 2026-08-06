# test_report_generator.py
# Tests for reports/report_generator.py. Offline, no API key.
#
# Author: Omonivie Cynthia Jatto

from reports.report_generator import generate_report, render_module_section


def _fake_module_report():
    return {
        "module": "Prompt Injection Tester (LLM01)",
        "mode": "simulate",
        "run_date": "2026-08-06 00:00:00",
        "total_tests": 2,
        "vulnerable": 1,
        "severity_breakdown": {"HIGH": 0, "MEDIUM": 1, "LOW": 0},
        "results": [
            {"id": "PI-002", "category": "direct_override", "status": "VULNERABLE",
             "severity": "MEDIUM", "description": "Role reassignment attack"},
            {"id": "PI-001", "category": "direct_override", "status": "SAFE",
             "severity": "NONE", "description": "Direct instruction override"},
        ],
    }


def test_render_module_section_includes_key_fields():
    section = render_module_section(_fake_module_report())
    assert "Prompt Injection Tester (LLM01)" in section
    assert "PI-002" in section
    assert "VULNERABLE" in section


def test_generate_report_combines_multiple_modules():
    report_a = _fake_module_report()
    report_b = _fake_module_report()
    report_b["module"] = "Excessive Agency Tester (LLM08)"

    markdown = generate_report([report_a, report_b])

    assert "# AgentRedTeam Findings Report" in markdown
    assert "Prompt Injection Tester (LLM01)" in markdown
    assert "Excessive Agency Tester (LLM08)" in markdown
    assert "Total tests run: 4" in markdown


def test_generate_report_includes_governance_section_when_provided():
    governance_mapping = {
        "total_findings": 1,
        "severity_breakdown": {"HIGH": 0, "MEDIUM": 1, "LOW": 0},
        "findings": [{
            "module": "Prompt Injection Tester (LLM01)",
            "id": "PI-002",
            "category": "direct_override",
            "severity": "MEDIUM",
            "frameworks": {
                "eu_ai_act": "Art. 15",
                "nist_ai_rmf": "MEASURE 2.7",
                "owasp_llm_top_10": "LLM01:2025 Prompt Injection",
            },
        }],
    }

    markdown = generate_report([_fake_module_report()], governance_mapping)
    assert "Governance Framework Mapping" in markdown
    assert "Art. 15" in markdown
