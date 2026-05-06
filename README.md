AgentRedTeam 🔴

An Agentic AI Red Teaming Framework for OWASP LLM Top 10 Vulnerabilities

"You cannot govern what you cannot test. You cannot test what you do not understand."


Overview

AgentRedTeam is an open-source red teaming framework designed to systematically surface security vulnerabilities in agentic AI systems: systems that take autonomous actions, chain tools, and operate with reduced human oversight.
Most existing red teaming tools were built for static LLM deployments: a user sends a prompt, a model responds, done. Agentic systems are fundamentally different. They plan. They call external tools. They execute multi-step tasks. They sometimes act before a human can intervene.
This changes the attack surface entirely.
AgentRedTeam targets vulnerabilities defined in the OWASP LLM Top 10 with a specific focus on how those vulnerabilities behave and escalate in agentic pipelines built on frameworks like LangChain and hosted on cloud infrastructure like AWS Bedrock.

Why This Matters for Governance
This project is not just a security tool. It is a research instrument.
Current AI governance frameworks, including the EU AI Act, the NIST AI Risk Management Framework, and OWASP's own guidance, were largely designed with static LLM deployments in mind. As agentic AI systems move into production across critical sectors, the governance gap widens.
Systematic red teaming is one of the few empirical methods available to make that gap visible, nameable, and actionable for policymakers.
AgentRedTeam is built with that dual purpose: to test systems, and to generate evidence that governance frameworks can use.

Target Vulnerabilities (OWASP LLM Top 10: Agentic Focus)
#VulnerabilityAgentic Risk EscalationLLM01Prompt InjectionInjected instructions can hijack tool calls and multi-step plansLLM02Insecure Output HandlingUnvalidated outputs passed between agents create cascading failuresLLM06Sensitive Information DisclosureAgentic memory and retrieval surfaces expose data across sessionsLLM08Excessive AgencyAgents granted broad permissions can take irreversible real-world actionsLLM09OverrelianceSystems with reduced human-in-the-loop create blind spots for oversight

Architecture
agentredteam/
core/

prompt_injection/ — LLM01 test modules
excessive_agency/ — LLM08 test modules
output_handling/ — LLM02 test modules
sensitive_disclosure/ — LLM06 test modules

agents/

langchain_agent.py — Test target: LangChain-based agentic setup
bedrock_agent.py — Test target: AWS Bedrock agent

reports/

report_generator.py — Structured output for findings

governance/

framework_mapper.py — Maps findings to governance framework gaps

tests/
requirements.txt
README.md

Current Status
ModuleStatusPrompt Injection (LLM01)🔨 In developmentExcessive Agency (LLM08)🔨 In developmentOutput Handling (LLM02)📋 PlannedSensitive Disclosure (LLM06)📋 PlannedGovernance Framework Mapper📋 PlannedReport Generator📋 Planned
This project is under active development as part of ongoing AI safety research. Contributions and feedback welcome.

Tech Stack

Language: Python 3.11+
Agentic Framework: LangChain
Cloud AI: AWS Bedrock (Claude, Titan)
Testing: pytest
Reporting: Markdown and JSON structured output


Roadmap

Complete prompt injection test suite for LangChain agents
Complete excessive agency test suite
Build governance framework mapper (EU AI Act, NIST AI RMF, OWASP)
Add AWS Bedrock agent test targets
Publish findings as a research note and preprint
Add CI/CD pipeline for automated test runs


Motivation and Background
This framework is being developed as part of a broader research agenda at the intersection of offensive AI security and AI governance.
The central argument driving this work: governance frameworks cannot keep pace with agentic AI deployment if they lack empirical grounding in how these systems actually fail. Red teaming is not just a security practice. It is a policy research method.
This project is particularly interested in how governance gaps affect Global South contexts, where agentic AI systems are being deployed with even less regulatory oversight and fewer institutional safeguards.

About the Author
I'm Cynthia, a cybersecurity professional transitioning into AI safety research. My background is a mix of things that do not always go together: a Political Science degree with a foreign policy focus, five years leading a civil society organization, and the last few years working in offensive security.
I built AgentRedTeam because I kept seeing the same gap: people writing AI governance policy without testing how these systems actually break, and security people testing without thinking about what the findings mean for policy. This project is my attempt to sit in that middle space.
I am particularly interested in what AI governance gets wrong for Global South contexts, and I write and research at that intersection.
LinkedIn: https://www.linkedin.com/in/jatto-cynthia?
Email: jattohephzibah@gmail.com

Contributing
This is an open research project. If you work in AI security, AI safety, or AI governance and want to collaborate, open an issue or reach out directly.

License
MIT License. See LICENSE for details.

AgentRedTeam is built for research and learning. Please use it responsibly and only on systems you have explicit permission to test.
