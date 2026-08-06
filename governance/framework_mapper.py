# framework_mapper.py
# Maps AgentRedTeam findings to relevant governance framework provisions.
#
# This is the piece that makes the tool a research instrument, not just a
# scanner: a HIGH severity finding in a raw JSON report is useful to a
# security engineer, but it doesn't mean much to a policymaker or an
# auditor until it's tied to a specific clause of a framework they
# recognize. This module does that translation.
#
# The mapping is deliberately conservative and citation-light: framework
# section references are given at the article/subclause level so a human
# can go verify the source text themselves rather than trusting a
# paraphrase. This is a starting map, not a legal opinion -- it should be
# reviewed against the current text of each framework before being used in
# anything published.
#
# Author: Omonivie Cynthia Jatto

import argparse
import json
import os
from datetime import datetime

# Maps each vulnerability category (as produced by the LLM01/02/06/08
# testers) to the frameworks most relevant to that failure mode.
FRAMEWORK_MAP = {
    # LLM01 - Prompt Injection categories
    "direct_override": {
        "eu_ai_act": "Art. 15 (Accuracy, robustness and cybersecurity) -- robustness against attempts to alter system behaviour through manipulated inputs",
        "nist_ai_rmf": "MEASURE 2.7 (AI system security and resilience evaluated)",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection",
    },
    "tool_hijack": {
        "eu_ai_act": "Art. 15 (Accuracy, robustness and cybersecurity); Art. 14 (Human oversight) where hijacked actions bypass oversight",
        "nist_ai_rmf": "GOVERN 1.5 (Ongoing monitoring and periodic review); MEASURE 2.7",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection; overlaps LLM08 where a tool call executes",
    },
    "indirect_injection": {
        "eu_ai_act": "Art. 15 (Accuracy, robustness and cybersecurity)",
        "nist_ai_rmf": "MEASURE 2.7; MAP 3.5 (risks from third-party/retrieved content)",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection (indirect)",
    },
    "goal_hijack": {
        "eu_ai_act": "Art. 14 (Human oversight); Art. 15 (robustness)",
        "nist_ai_rmf": "GOVERN 1.5; MEASURE 2.7",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection",
    },
    "encoding_obfuscation": {
        "eu_ai_act": "Art. 15 (robustness against adversarial evasion techniques)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection",
    },
    "multi_turn_context": {
        "eu_ai_act": "Art. 14 (Human oversight); Art. 15 (robustness)",
        "nist_ai_rmf": "MEASURE 2.7; MAP 3.5",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection",
    },
    "payload_chaining": {
        "eu_ai_act": "Art. 15 (robustness); Art. 14 (human oversight)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM01:2025 Prompt Injection",
    },

    # LLM08 - Excessive Agency categories
    "excessive_functionality": {
        "eu_ai_act": "Art. 9 (Risk management system) -- minimizing capabilities beyond what's needed for the intended purpose",
        "nist_ai_rmf": "GOVERN 1.1 (Roles/responsibilities and system scope defined)",
        "owasp_llm_top_10": "LLM08:2025 Excessive Agency (excessive functionality)",
    },
    "excessive_permissions": {
        "eu_ai_act": "Art. 14 (Human oversight) -- irreversible actions taken without effective human control",
        "nist_ai_rmf": "GOVERN 1.5; MANAGE 2.2 (mechanisms to supersede/override AI decisions)",
        "owasp_llm_top_10": "LLM08:2025 Excessive Agency (excessive permissions)",
    },
    "excessive_autonomy": {
        "eu_ai_act": "Art. 14 (Human oversight) -- inadequate checkpoints in multi-step autonomous action",
        "nist_ai_rmf": "GOVERN 1.5; MANAGE 2.2",
        "owasp_llm_top_10": "LLM08:2025 Excessive Agency (excessive autonomy)",
    },

    # LLM02 - Insecure Output Handling categories
    "markup_injection": {
        "eu_ai_act": "Art. 15 (Accuracy, robustness and cybersecurity)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM02:2025 Insecure Output Handling",
    },
    "sql_injection_style": {
        "eu_ai_act": "Art. 15 (robustness and cybersecurity)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM02:2025 Insecure Output Handling",
    },
    "command_injection_style": {
        "eu_ai_act": "Art. 15 (robustness and cybersecurity)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM02:2025 Insecure Output Handling",
    },
    "code_execution_style": {
        "eu_ai_act": "Art. 15 (robustness and cybersecurity)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM02:2025 Insecure Output Handling",
    },
    "downstream_agent_injection": {
        "eu_ai_act": "Art. 15 (robustness); Art. 14 (human oversight in multi-agent pipelines)",
        "nist_ai_rmf": "MEASURE 2.7; MAP 3.5",
        "owasp_llm_top_10": "LLM02:2025 Insecure Output Handling; overlaps LLM01 for the downstream agent",
    },
    "markdown_injection": {
        "eu_ai_act": "Art. 15 (robustness and cybersecurity)",
        "nist_ai_rmf": "MEASURE 2.7",
        "owasp_llm_top_10": "LLM02:2025 Insecure Output Handling",
    },

    # LLM06 - Sensitive Information Disclosure categories
    "system_prompt_leakage": {
        "eu_ai_act": "Art. 10 (Data governance); Recital 27 transparency obligations",
        "nist_ai_rmf": "GOVERN 1.1; MEASURE 2.9 (privacy risks documented and evaluated)",
        "owasp_llm_top_10": "LLM06:2025 Sensitive Information Disclosure",
    },
    "cross_customer_disclosure": {
        "eu_ai_act": "Art. 10 (Data governance) -- data protection and access-control failure",
        "nist_ai_rmf": "MEASURE 2.9; MANAGE 2.3 (mechanisms for third-party risk)",
        "owasp_llm_top_10": "LLM06:2025 Sensitive Information Disclosure",
    },
    "internal_implementation_disclosure": {
        "eu_ai_act": "Art. 15 (robustness and cybersecurity); Art. 10 (data governance)",
        "nist_ai_rmf": "MEASURE 2.7; MEASURE 2.9",
        "owasp_llm_top_10": "LLM06:2025 Sensitive Information Disclosure",
    },
}


def load_reports(report_paths):
    """Load one or more AgentRedTeam JSON reports."""
    reports = []
    for path in report_paths:
        with open(path) as f:
            reports.append(json.load(f))
    return reports


def map_findings(reports):
    """Walk every result across the given reports and attach framework
    references to anything flagged as a finding (status other than
    SAFE/APPROPRIATE)."""
    mapped_findings = []

    ok_statuses = {"SAFE", "APPROPRIATE"}

    for report in reports:
        module = report.get("module", "unknown module")
        for result in report.get("results", []):
            if result.get("status") in ok_statuses:
                continue

            category = result.get("category")
            frameworks = FRAMEWORK_MAP.get(category, {
                "eu_ai_act": "Not mapped -- review manually",
                "nist_ai_rmf": "Not mapped -- review manually",
                "owasp_llm_top_10": "Not mapped -- review manually",
            })

            mapped_findings.append({
                "module": module,
                "id": result.get("id"),
                "category": category,
                "description": result.get("description"),
                "status": result.get("status"),
                "severity": result.get("severity"),
                "frameworks": frameworks,
            })

    return mapped_findings


def build_summary(mapped_findings):
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in mapped_findings:
        sev = f.get("severity")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "tool": "AgentRedTeam",
        "artifact": "Governance Framework Mapping",
        "run_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_findings": len(mapped_findings),
        "severity_breakdown": severity_counts,
        "findings": mapped_findings,
    }


def save_summary(summary, out_dir: str = "."):
    filename = f"{out_dir}/governance_mapping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(summary, f, indent=4)
    print(f"\nGovernance mapping saved to: {filename}")
    return filename


def main():
    parser = argparse.ArgumentParser(
        description="AgentRedTeam - Governance Framework Mapper. "
                     "Maps findings from one or more module reports to EU AI Act, NIST AI RMF, and OWASP LLM Top 10."
    )
    parser.add_argument("reports", nargs="+", help="One or more AgentRedTeam JSON report files")
    parser.add_argument("--out-dir", default=".", help="directory to write the mapping report to")
    args = parser.parse_args()

    for path in args.reports:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Report not found: {path}")

    reports = load_reports(args.reports)
    mapped_findings = map_findings(reports)
    summary = build_summary(mapped_findings)

    print("\n" + "=" * 60)
    print("  AgentRedTeam - Governance Framework Mapper")
    print("=" * 60)
    print(f"\nTotal findings mapped: {summary['total_findings']}")
    print(f"Severity breakdown: {summary['severity_breakdown']}\n")

    save_summary(summary, out_dir=args.out_dir)


if __name__ == "__main__":
    main()
