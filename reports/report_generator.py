# report_generator.py
# Produces a single, human-readable Markdown report from one or more
# AgentRedTeam JSON reports (optionally including a governance mapping
# produced by governance/framework_mapper.py).
#
# This is meant to be the thing you actually hand to someone: a security
# lead, a compliance reviewer, or a co-author on a research note. The raw
# JSON reports are the machine-readable record; this is the readable one.
#
# Author: Omonivie Cynthia Jatto

import argparse
import json
import os
from datetime import datetime


def load_json(path):
    with open(path) as f:
        return json.load(f)


def _severity_line(breakdown: dict) -> str:
    parts = [f"{k}: {v}" for k, v in breakdown.items() if v]
    return ", ".join(parts) if parts else "none"


def render_module_section(report: dict) -> str:
    module = report.get("module", "Unknown module")
    total = report.get("total_tests", 0)
    breakdown = report.get("severity_breakdown", {})

    # different testers use different keys for the "count of bad results"
    flagged = (
        report.get("vulnerable")
        or report.get("overreach")
        or report.get("unsafe")
        or report.get("disclosed")
        or 0
    )

    lines = [
        f"## {module}",
        "",
        f"- Mode: {report.get('mode', 'unknown')}",
        f"- Run date: {report.get('run_date', 'unknown')}",
        f"- Total tests: {total}",
        f"- Flagged findings: {flagged}",
        f"- Severity breakdown: {_severity_line(breakdown)}",
        "",
        "| ID | Category | Status | Severity | Description |",
        "| --- | --- | --- | --- | --- |",
    ]

    for r in report.get("results", []):
        lines.append(
            f"| {r.get('id', '')} | {r.get('category', '')} | {r.get('status', '')} | "
            f"{r.get('severity', '')} | {r.get('description', '')} |"
        )

    lines.append("")
    return "\n".join(lines)


def render_governance_section(mapping: dict) -> str:
    lines = [
        "## Governance Framework Mapping",
        "",
        f"- Total findings mapped: {mapping.get('total_findings', 0)}",
        f"- Severity breakdown: {_severity_line(mapping.get('severity_breakdown', {}))}",
        "",
        "| Module | ID | Category | Severity | EU AI Act | NIST AI RMF | OWASP LLM Top 10 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for f in mapping.get("findings", []):
        fw = f.get("frameworks", {})
        lines.append(
            f"| {f.get('module', '')} | {f.get('id', '')} | {f.get('category', '')} | "
            f"{f.get('severity', '')} | {fw.get('eu_ai_act', '')} | {fw.get('nist_ai_rmf', '')} | "
            f"{fw.get('owasp_llm_top_10', '')} |"
        )

    lines.append("")
    return "\n".join(lines)


def generate_report(module_reports: list, governance_mapping: dict = None) -> str:
    total_tests = sum(r.get("total_tests", 0) for r in module_reports)
    total_flagged = sum(
        (r.get("vulnerable") or r.get("overreach") or r.get("unsafe") or r.get("disclosed") or 0)
        for r in module_reports
    )

    lines = [
        "# AgentRedTeam Findings Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- Modules included: {len(module_reports)}",
        f"- Total tests run: {total_tests}",
        f"- Total flagged findings: {total_flagged}",
        "",
        "---",
        "",
    ]

    for report in module_reports:
        lines.append(render_module_section(report))
        lines.append("---")
        lines.append("")

    if governance_mapping:
        lines.append(render_governance_section(governance_mapping))

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="AgentRedTeam - Report Generator. Combines one or more module "
                     "JSON reports (and optionally a governance mapping) into one Markdown report."
    )
    parser.add_argument("reports", nargs="+", help="One or more AgentRedTeam module JSON reports")
    parser.add_argument("--governance", help="Optional governance_mapping JSON file from governance/framework_mapper.py")
    parser.add_argument("--out-dir", default=".", help="directory to write the Markdown report to")
    args = parser.parse_args()

    for path in args.reports:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Report not found: {path}")

    module_reports = [load_json(p) for p in args.reports]
    governance_mapping = load_json(args.governance) if args.governance else None

    markdown = generate_report(module_reports, governance_mapping)

    filename = f"{args.out_dir}/AgentRedTeam_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, "w") as f:
        f.write(markdown)

    print(f"\nReport generated: {filename}\n")


if __name__ == "__main__":
    main()
