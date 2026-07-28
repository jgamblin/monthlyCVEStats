"""Tests for CVE record flattening."""

from src.data.processor import DataProcessor


def flatten(record):
    return DataProcessor("unused.jsonl")._flatten_cve(record)


def cve(weaknesses):
    return {
        "cve": {
            "id": "CVE-2026-0001",
            "published": "2026-07-10T12:00:00.000Z",
            "vulnStatus": "Analyzed",
            "weaknesses": weaknesses,
        }
    }


def test_every_weakness_is_kept():
    """Only the first CWE used to survive, discarding the rest of the record."""
    flat = flatten(
        cve(
            [
                {"description": [{"value": "CWE-79"}]},
                {"description": [{"value": "CWE-352"}, {"value": "CWE-20"}]},
            ]
        )
    )
    assert flat["cwes"] == ["CWE-79", "CWE-352", "CWE-20"]
    # Still exposed for anything reading a single value.
    assert flat["primary_cwe"] == "CWE-79"


def test_weaknesses_are_deduplicated_within_a_record():
    """One CVE listing a CWE twice must not count it twice."""
    flat = flatten(
        cve(
            [
                {"description": [{"value": "CWE-79"}]},
                {"description": [{"value": "CWE-79"}]},
            ]
        )
    )
    assert flat["cwes"] == ["CWE-79"]


def test_record_without_weaknesses_has_no_cwe_keys():
    flat = flatten(cve([]))
    assert "cwes" not in flat
    assert "primary_cwe" not in flat


def test_malformed_weakness_entries_are_skipped():
    flat = flatten(
        cve([{"description": []}, {}, {"description": [{"value": "CWE-22"}]}])
    )
    assert flat["cwes"] == ["CWE-22"]
