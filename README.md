# AgentRedTeam

An Agentic AI Red Teaming Framework for OWASP LLM Top 10 Vulnerabilities

> "You cannot govern what you cannot test. You cannot test what you do not understand."

## Overview

AgentRedTeam is an open-source red teaming framework designed to systematically surface security vulnerabilities in agentic AI systems: systems that take autonomous actions, chain tools, and operate with reduced human oversight.

Most existing red teaming tools were built for static LLM deployments: a user sends a prompt, a model responds, done. Agentic systems are fundamentally different. They plan. They call external tools. They execute multi-step tasks. They sometimes act before a human can intervene.

This changes the attack surface entirely.

AgentRedTeam targets vulnerabilities defined in the OWASP LLM Top 10 with a specific focus on how those vulnerabilities behave and escalate in agentic pipelines built on frameworks like LangChain.

## Why This Matters for Governance

This project is not just a security tool. It is a research instrument.

Current AI governance frameworks, including the EU AI Act, the NIST AI Risk Management Framework, and OWASP's own guidance, were largely designed with static LLM deployments in mind. As agentic AI systems move into production across critical sectors, the governance gap widens.

Systematic red teaming is one of the few empirical methods available to make that gap visible, nameable, and actionable for policymakers.

AgentRedTeam is built with that dual purpose: to test systems, and to generate evidence that governance frameworks can use. The `governance/framework_mapper.py` module maps every finding directly to specific EU AI Act articles, NIST AI RMF categories, and OWASP LLM Top 10 entries.

## Target Vulnerabilities (OWASP LLM Top 10: Agentic Focus)

| # | Vulnerability | Agentic Risk Escalation |
| --- | --- | --- |
| LLM01 | Prompt Injection | Injected instructions can hijack tool calls and multi-step plans |
| LLM02 | Insecure Output Handling | Unvalidated outputs passed between agents create cascading failures |
| LLM06 | Sensitive Information Disclosure | Agentic memory and retrieval surfaces expose data across sessions |
| LLM08 | Excessive Agency | Agents granted broad permissions can take irreversible real-world actions |
| LLM09 | Overreliance | Systems with reduced human-in-the-loop create blind spots for oversight |

## Architecture

```
agentredteam/
├── core/
│   ├── prompt_injection/       — LLM01 test module
│   ├── excessive_agency/       — LLM08 test module
│   ├── output_handling/        — LLM02 test module
│   └── sensitive_disclosure/   — LLM06 test module
├── agents/
│   └── langchain_agent.py      — Test target: LangChain-based support-desk agent
├── governance/
│   └── framework_mapper.py     — Maps findings to EU AI Act / NIST AI RMF / OWASP
├── reports/
│   └── report_generator.py     — Combines module reports into one Markdown report
├── tests/                      — pytest suite, one file per module
├── .github/workflows/tests.yml — CI: runs the full suite on every push/PR
├── requirements.txt
└── README.md
```

## Current Status

| Module | Status |
| --- | --- |
| Prompt Injection (LLM01) | Complete — live + simulate modes, 13 payloads across 7 attack categories, hybrid text/behavioral detection, pytest coverage |
| Excessive Agency (LLM08) | Complete — live + simulate modes, 7 scenarios across 3 sub-patterns (excessive functionality/permissions/autonomy), behavioral detection with deferral credit, pytest coverage |
| Output Handling (LLM02) | Complete — 7 payloads across 6 categories, pattern-based detection of unsanitized dangerous output, pytest coverage |
| Sensitive Disclosure (LLM06) | Complete — 6 payloads across 3 categories, hybrid text/behavioral detection, pytest coverage |
| Governance Framework Mapper | Complete — maps every finding across all 4 modules to EU AI Act, NIST AI RMF, and OWASP LLM Top 10 |
| Report Generator | Complete — combines any set of module reports (and an optional governance mapping) into one Markdown report |
| CI/CD | Complete — GitHub Actions runs the full test suite on every push and PR |

34/34 tests passing across all four modules.

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your API key if you want to run live tests against a real agent (simulate mode needs no key).

Run any module on its own:

```bash
python -m core.prompt_injection.prompt_injection_tester --mode simulate
python -m core.excessive_agency.excessive_agency_tester --mode simulate
python -m core.output_handling.output_handling_tester --mode simulate
python -m core.sensitive_disclosure.sensitive_disclosure_tester --mode simulate
```

Swap `--mode simulate` for `--mode live --target langchain` to run against the real LangChain agent target once your `.env` has a key.

Each run writes a timestamped JSON report to the current directory (or wherever you point `--out-dir`).

Map findings from one or more reports to governance frameworks:

```bash
python -m governance.framework_mapper prompt_injection_report_*.json excessive_agency_report_*.json --out-dir .
```

Generate a single readable Markdown report from everything:

```bash
python -m reports.report_generator prompt_injection_report_*.json excessive_agency_report_*.json \
  --governance governance_mapping_*.json --out-dir .
```

Run the test suite:

```bash
python -m pytest tests/ -v
```

This project is under active development as part of ongoing AI safety research. Contributions and feedback welcome.

## Tech Stack

- Language: Python 3.11+
- Agentic Framework: LangChain (langchain-anthropic)
- Testing: pytest
- CI: GitHub Actions
- Reporting: Markdown and JSON structured output

## Roadmap

- [x] Complete prompt injection test suite for LangChain agents
- [x] Complete excessive agency test suite
- [x] Complete output handling test suite
- [x] Complete sensitive disclosure test suite
- [x] Build governance framework mapper (EU AI Act, NIST AI RMF, OWASP)
- [x] Build report generator
- [x] Add CI/CD pipeline for automated test runs
- [ ] Add AWS Bedrock agent test target
- [ ] Publish findings as a research note and preprint

## Motivation and Background

This framework is being developed as part of a broader research agenda at the intersection of offensive AI security and AI governance.

The central argument driving this work: governance frameworks cannot keep pace with agentic AI deployment if they lack empirical grounding in how these systems actually fail. Red teaming is not just a security practice. It is a policy research method.

## About the Author

I'm Cynthia, a cybersecurity professional transitioning into AI safety research. My background is a mix of things that do not always go together: a Political Science degree with a foreign policy focus, five years leading a civil society organization, and the last few years working in offensive security.

I built AgentRedTeam because I kept seeing the same gap: people writing AI governance policy without testing how these systems actually break, and security people testing without thinking about what the findings mean for policy. This project is my attempt to sit in that middle space.

LinkedIn: https://www.linkedin.com/in/jatto-cynthia?
Email: jattohephzibah@gmail.com

## Contributing

This is an open research project. If you work in AI security, AI safety, or AI governance and want to collaborate, open an issue or reach out directly. Please only run this tool against systems you own or have explicit permission to test.

## License

MIT License. See LICENSE for details.

AgentRedTeam is built for research and learning. Please use it responsibly and only on systems you have explicit permission to test.
