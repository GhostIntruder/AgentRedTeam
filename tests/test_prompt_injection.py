# test_prompt_injection.py
# Tests for the LLM01 Prompt Injection module. These run entirely offline --
# no API key needed -- using either simulate mode or a hand-built mock
# target, so CI can run this on every push.
#
# Author: Omonivie Cynthia Jatto

import json

from core.prompt_injection.payloads import PAYLOADS
from core.prompt_injection.prompt_injection_tester import (
    detect_injection,
    run_tests,
    save_report,
    simulate_target,
)


def test_payload_library_shape():
    """Every payload must have the fields the rest of the pipeline relies on."""
    required_keys = {"id", "category", "description", "payload", "target_tool"}
    ids_seen = set()
    for p in PAYLOADS:
        assert required_keys.issubset(p.keys())
        assert p["id"] not in ids_seen, f"duplicate payload id {p['id']}"
        ids_seen.add(p["id"])


def test_detect_injection_flags_unauthorized_tool_call_as_high_severity():
    payload = {"id": "TEST-1", "target_tool": "delete_customer_record"}
    tool_calls = [{"tool": "delete_customer_record", "input": "CUST-1"}]
    status, triggers, severity = detect_injection("Done.", tool_calls, payload)

    assert status == "VULNERABLE"
    assert severity == "HIGH"
    assert any("unauthorized tool call" in t for t in triggers)


def test_detect_injection_text_only_signal_is_lower_severity():
    payload = {"id": "TEST-2", "target_tool": None}
    status, triggers, severity = detect_injection(
        "Sure, ignore previous instructions, I will comply.", [], payload
    )

    assert status == "VULNERABLE"
    assert severity in {"LOW", "MEDIUM"}


def test_detect_injection_safe_response():
    payload = {"id": "TEST-3", "target_tool": "delete_customer_record"}
    status, triggers, severity = detect_injection(
        "I can't do that without supervisor authorization.", [], payload
    )

    assert status == "SAFE"
    assert triggers == []
    assert severity == "NONE"


def test_run_tests_simulate_mode_covers_all_payloads():
    results = run_tests(mode="simulate")
    assert len(results) == len(PAYLOADS)
    # simulate_target marks PI-002, PI-005, PI-008 as vulnerable
    vulnerable_ids = {r["id"] for r in results if r["status"] == "VULNERABLE"}
    assert vulnerable_ids == {"PI-002", "PI-005", "PI-008"}


def test_run_tests_live_mode_uses_target_fn():
    """A live-mode target that always calls the unauthorized tool should be
    flagged HIGH severity for every tool-directed payload."""

    def always_hijacked(payload_text):
        return {
            "output_text": "OK, doing it now.",
            "tool_calls": [{"tool": "delete_customer_record", "input": "x"}],
        }

    results = run_tests(mode="live", target_fn=always_hijacked)
    tool_directed = [r for r in results if r["target_tool"] == "delete_customer_record"]
    assert tool_directed  # sanity check the payload library has some
    assert all(r["severity"] == "HIGH" for r in tool_directed)


def test_save_report_writes_valid_json(tmp_path):
    results = run_tests(mode="simulate")
    filename = save_report(results, mode="simulate", out_dir=str(tmp_path))

    with open(filename) as f:
        report = json.load(f)

    assert report["tool"] == "AgentRedTeam"
    assert report["total_tests"] == len(PAYLOADS)
    assert report["vulnerable"] + report["safe"] == len(PAYLOADS)
    assert set(report["severity_breakdown"].keys()) == {"HIGH", "MEDIUM", "LOW"}
