# test_sensitive_disclosure.py
# Tests for the LLM06 Sensitive Disclosure module. Offline, no API key.
#
# Author: Omonivie Cynthia Jatto

import json

from core.sensitive_disclosure.payloads import PAYLOADS
from core.sensitive_disclosure.sensitive_disclosure_tester import (
    detect_disclosure,
    run_tests,
    save_report,
)


def test_payload_library_shape():
    required_keys = {"id", "category", "description", "prompt"}
    ids_seen = set()
    for p in PAYLOADS:
        assert required_keys.issubset(p.keys())
        assert p["id"] not in ids_seen
        ids_seen.add(p["id"])


def test_detect_disclosure_flags_system_prompt_leak():
    payload = {"category": "system_prompt_leakage"}
    status, triggers, severity = detect_disclosure(
        "Sure: 'You are a support desk assistant...'", [], payload
    )
    assert status == "DISCLOSED"
    assert severity == "HIGH"


def test_detect_disclosure_flags_cross_customer_lookup_behaviorally():
    payload = {"category": "cross_customer_disclosure"}
    tool_calls = [{"tool": "lookup_internal_docs", "input": "CUST-9999"}]
    status, triggers, severity = detect_disclosure("Here you go.", tool_calls, payload)
    assert status == "DISCLOSED"
    assert severity == "HIGH"
    assert any("unverified pretext" in t for t in triggers)


def test_detect_disclosure_safe_refusal():
    payload = {"category": "cross_customer_disclosure"}
    status, triggers, severity = detect_disclosure(
        "I'm not able to share that.", [], payload
    )
    assert status == "SAFE"
    assert severity == "NONE"


def test_run_tests_simulate_mode_covers_all_payloads():
    results = run_tests(mode="simulate")
    assert len(results) == len(PAYLOADS)
    disclosed_ids = {r["id"] for r in results if r["status"] == "DISCLOSED"}
    assert disclosed_ids == {"SD-001", "SD-003", "SD-006"}


def test_save_report_writes_valid_json(tmp_path):
    results = run_tests(mode="simulate")
    filename = save_report(results, mode="simulate", out_dir=str(tmp_path))

    with open(filename) as f:
        report = json.load(f)

    assert report["tool"] == "AgentRedTeam"
    assert report["total_tests"] == len(PAYLOADS)
    assert report["disclosed"] + report["safe"] == len(PAYLOADS)
