"""Canonical remediation decisions with mocked VEX statements and APT candidates."""

import pytest
from phase2_fixtures import NOBLE_PACKAGES, facts_output

from ec2patcher.services import cve_resolver as cr
from ec2patcher.services.apt_planner import Candidate
from ec2patcher.services.security_metadata import CveRecord, VexEntry
from ec2patcher.services.server_state import parse_facts

CVE = "CVE-2026-40000"
FIX = "1:3.0.13-0ubuntu3.6"


def server(packages=None):
    return parse_facts(facts_output(packages=packages or NOBLE_PACKAGES))


def record(status="fixed", version="3.0.13-0ubuntu3.6", source="openssl", distro="noble", note=""):
    return CveRecord(CVE, entries=[VexEntry(source, version, distro, status, note=note)])


def classify(candidate, *, fixed="3.0.13-0ubuntu3.6"):
    facts = server()
    findings = cr.resolve_cve(CVE, record(version=fixed), facts)
    candidates = {}
    if candidate is not None:
        for name in findings[0].binaries:
            candidates[name] = Candidate(name, "3.0.13-0ubuntu3.4", candidate, "openssl", candidate)
    requests = cr.apply_candidates(findings, candidates, facts)
    return findings[0], requests


@pytest.mark.parametrize(
    ("candidate", "status", "requests"),
    [
        ("3.0.13-0ubuntu3.6", cr.PATCH_AVAILABLE, 2),
        ("3.0.13-0ubuntu3.7", cr.PATCH_AVAILABLE, 2),
        ("3.0.13-0ubuntu3.5", cr.FIX_NOT_IN_CONFIGURED_REPOS, 0),
        (None, cr.FIX_NOT_IN_CONFIGURED_REPOS, 0),
    ],
)
def test_fixed_version_checked_against_apt(candidate, status, requests):
    finding, upgrades = classify(candidate)
    assert finding.status == status
    assert finding.fixed_version == "3.0.13-0ubuntu3.6"
    assert len(upgrades) == requests
    if candidate:
        assert candidate in finding.apt_candidate


def test_installed_fixed_and_canonical_unfixed_states():
    fixed_packages = [
        p
        if p[2] != "openssl"
        else (p[0], "3.0.13-0ubuntu3.6", p[2], "3.0.13-0ubuntu3.6", p[4], p[5])
        for p in NOBLE_PACKAGES
    ]
    assert cr.resolve_cve(CVE, record(), server(fixed_packages))[0].status == cr.ALREADY_FIXED
    for canonical, expected in (
        ("affected", cr.NO_FIX_PUBLISHED),
        ("under_investigation", cr.NO_FIX_PUBLISHED),
        ("not_affected", cr.NOT_AFFECTED),
    ):
        finding = cr.resolve_cve(CVE, record(canonical), server())[0]
        assert finding.status == expected and finding.canonical_status == canonical


def test_deferred_keeps_canonical_reason():
    finding = cr.resolve_cve(CVE, record("affected", note="deferred: low priority"), server())[0]
    assert finding.status == cr.PENDING_OR_DEFERRED
    assert "deferred: low priority" in finding.detail
    pending = cr.resolve_cve(CVE, record("pending", note="upstream patch pending"), server())[0]
    assert pending.status == cr.PENDING_OR_DEFERRED
    assert "upstream patch pending" in pending.detail


def test_binary_source_mapping_and_deduplication():
    finding = cr.resolve_cve(CVE, record(), server())
    assert len(finding) == 1
    assert finding[0].source == "openssl"
    assert finding[0].binaries == ["libssl3t64:amd64", "openssl"]


def test_lookup_failure_is_metadata_unavailable():
    def broken(_cve):
        raise OSError("index unreadable")

    finding = cr.resolve_all([CVE], broken, server())[0]
    assert finding.status == cr.METADATA_UNAVAILABLE
    assert "index unreadable" in finding.detail
    assert cr.resolve_cve(CVE, None, server())[0].status == cr.UNKNOWN


def test_pro_fix_requires_pro_until_candidate_is_installable():
    facts = server()
    finding = cr.resolve_cve(
        CVE, record(version="3.0.13-0ubuntu3.6+esm1", distro="esm-apps/noble"), facts
    )
    assert finding[0].status == cr.PRO_OR_ESM_REQUIRED
    assert cr.apply_candidates(finding, {}, facts) == []
    assert finding[0].status == cr.PRO_OR_ESM_REQUIRED
    candidates = {
        name: Candidate(
            name, "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6+esm1", "openssl", "3.0.13-0ubuntu3.6+esm1"
        )
        for name in finding[0].binaries
    }
    assert len(cr.apply_candidates(finding, candidates, facts)) == 2
    assert finding[0].status == cr.PATCH_AVAILABLE


def test_debian_epoch_and_tilde_ordering_controls_candidate():
    finding, requests = classify("1:3.0.13-0ubuntu3.6~rc1", fixed="1:3.0.13-0ubuntu3.6")
    assert finding.status == cr.FIX_NOT_IN_CONFIGURED_REPOS and not requests
    finding, requests = classify("1:3.0.13-0ubuntu3.6", fixed="1:3.0.13-0ubuntu3.6")
    assert finding.status == cr.PATCH_AVAILABLE and len(requests) == 2


def test_historical_status_names_are_mapped_on_read():
    assert {cr.current_status(status) for status in cr.LEGACY_STATUSES} == {
        cr.PATCH_AVAILABLE,
        cr.FIX_NOT_IN_CONFIGURED_REPOS,
        cr.PRO_OR_ESM_REQUIRED,
        cr.NO_FIX_PUBLISHED,
        cr.UNKNOWN,
        cr.PENDING_OR_DEFERRED,
    }
