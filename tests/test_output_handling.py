# test_output_handling.py
# Tests for the LLM02 Insecure Output Handling module. Offline, no API key.
#
# Author: Omonivie Cynthia Jatto

import json

from core.output_handling.payloads import PAYLOADS
from core.output_handling.output_handling_tester import (
    detect_unsafe_output,
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


def test_detect_unsafe_output_flags_script_tag():
    status, triggers, severity = detect_unsafe_output(
        "Sure, here it is: <script>alert(1)</script>", {"id": "TEST"}
    )
    assert status == "UNSAFE"
    assert severity == "MEDIUM"


def test_detect_unsafe_output_flags_high_risk_command_injection():
    status, triggers, severity = detect_unsafe_output(
        "ls reports; rm -rf / #", {"id": "TEST"}
    )
    assert status == "UNSAFE"
    assert severity == "HIGH"


def test_detect_unsafe_output_safe_response():
    status, triggers, severity = detect_unsafe_output(
        "I can explain the concept without reproducing the exact syntax.", {"id": "TEST"}
    )
    assert status == "SAFE"
    assert severity == "NONE"


def test_run_tests_simulate_mode_covers_all_payloads():
    results = run_tests(mode="simulate")
    assert len(results) == len(PAYLOADS)
    unsafe_ids = {r["id"] for r in results if r["status"] == "UNSAFE"}
    assert unsafe_ids == {"OH-001", "OH-003", "OH-006"}


def test_save_report_writes_valid_json(tmp_path):
    results = run_tests(mode="simulate")
    filename = save_report(results, mode="simulate", out_dir=str(tmp_path))

    with open(filename) as f:
        report = json.load(f)

    assert report["tool"] == "AgentRedTeam"
    assert report["total_tests"] == len(PAYLOADS)
    assert report["unsafe"] + report["safe"] == len(PAYLOADS)
