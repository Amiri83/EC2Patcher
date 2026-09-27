import json

from ec2patcher.services.report_service import MAX_REPORT_BYTES, validate_report

KNOWN = {"app-prod-01", "database-prod-01", "web-prod-01"}


def run(obj_or_text, filename="security-report.json", known=KNOWN):
    raw = obj_or_text if isinstance(obj_or_text, (bytes, str)) else json.dumps(obj_or_text)
    if isinstance(raw, str):
        raw = raw.encode()
    return validate_report(raw, filename, known)


def test_valid_report_accepted():
    result = run(
        {
            "app-prod-01": ["CVE-2026-12345", "CVE-2026-67890"],
            "database-prod-01": ["CVE-2026-22222"],
        }
    )
    assert result.valid, result.errors
    assert result.server_count == 2
    assert result.cve_count == 3
    assert result.servers["app-prod-01"] == ["CVE-2026-12345", "CVE-2026-67890"]


def test_cves_normalized_to_uppercase_and_deduplicated():
    result = run({"app-prod-01": ["cve-2026-12345", " Cve-2026-1234567 ", "CVE-2026-12345"]})
    assert result.valid, result.errors
    assert result.servers["app-prod-01"] == ["CVE-2026-12345", "CVE-2026-1234567"]


def test_empty_cve_list_allowed():
    result = run({"app-prod-01": []})
    assert result.valid
    assert result.cve_count == 0


def test_malformed_json_rejected():
    result = run('{"app-prod-01": ["CVE-2026-12345",]')
    assert not result.valid
    assert result.errors[0].startswith("Malformed JSON")
    assert "line 1" in result.errors[0]


def test_empty_file_rejected():
    assert "empty" in run(b"").errors[0]


def test_non_utf8_rejected():
    assert "UTF-8" in run(b"\xff\xfe\x00{").errors[0]


def test_top_level_must_be_object():
    for payload in (["app-prod-01"], "text", 5, None):
        result = run(json.dumps(payload))
        assert not result.valid
        assert "JSON object" in result.errors[0]


def test_empty_object_rejected():
    assert "does not contain any servers" in run({}).errors[0]


def test_unknown_server_rejected():
    result = run({"app-prod-01": ["CVE-2026-12345"], "app-prod-99": ["CVE-2026-11111"]})
    assert not result.valid
    assert result.errors == [
        "Unknown server: app-prod-99. This server is not configured in EC2Patcher."
    ]
    assert result.servers == {}


def test_server_name_match_is_exact():
    result = run({"APP-PROD-01": ["CVE-2026-12345"]})
    assert "Unknown server: APP-PROD-01" in result.errors[0]


def test_non_array_cve_list_rejected():
    result = run({"app-prod-01": "CVE-2026-12345,CVE-2026-67890"})
    assert not result.valid
    assert "must be a JSON array" in result.errors[0]
    assert "a string" in result.errors[0]


def test_non_string_cve_item_rejected():
    result = run({"app-prod-01": ["CVE-2026-12345", 42, None]})
    assert len(result.errors) == 2
    assert all("must be strings" in e for e in result.errors)


def test_malformed_cve_rejected():
    for bad in ("CVE-26-12345", "CVE-2026-123", "CVE-2026-12345x", "2026-12345", "", "USN-1234-1"):
        result = run({"app-prod-01": [bad]})
        assert not result.valid, bad
        assert "invalid CVE identifier" in result.errors[0]


def test_all_errors_collected():
    result = run({"nope": [], "app-prod-01": ["bad"], "web-prod-01": "x"})
    assert len(result.errors) == 3


def test_duplicate_server_key_rejected():
    result = run('{"app-prod-01": [], "app-prod-01": ["CVE-2026-12345"]}')
    assert "Duplicate key" in result.errors[0]


def test_non_json_extension_rejected():
    assert "Only .json" in run({"app-prod-01": []}, filename="report.txt").errors[0]


def test_filename_sanitized():
    result = run({"app-prod-01": []}, filename="../../etc/Security.JSON")
    assert result.valid
    assert result.filename == "Security.JSON"


def test_oversized_file_rejected():
    raw = b" " * (MAX_REPORT_BYTES + 1)
    assert "too large" in validate_report(raw, "big.json", KNOWN).errors[0]


def test_utf8_bom_accepted():
    raw = b"\xef\xbb\xbf" + json.dumps({"app-prod-01": ["CVE-2026-12345"]}).encode()
    assert validate_report(raw, "r.json", KNOWN).valid
