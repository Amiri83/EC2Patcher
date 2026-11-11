"""Canonical's OVAL criterion wordings: source package, Pro pocket, quoted kernel, the old form."""

import bz2
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

import pytest
from phase2_fixtures import facts_output

from ec2patcher.services import cve_resolver, oval_feed
from ec2patcher.services.server_state import parse_facts

FIXTURES = Path(__file__).parent / "fixtures"
FORMS_XML = (FIXTURES / "oval_forms.cve.oval.xml").read_bytes()
NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
START = datetime(2000, 1, 1, tzinfo=timezone.utc)
KNOWN = (
    "example-package source package in noble, was vulnerable but has been fixed (note: '1.0-1')."
)
UNKNOWN = (
    "example-package frobnicated in noble, an unheard-of wording.",
    "example-package source package in noble, has transcended.",  # known form, unknown status
)


def entries(xml: bytes = FORMS_XML) -> dict:
    return {(e.cve, e.package): e for e in oval_feed.parse_oval(io.BytesIO(xml))}


def fetcher_of(xml: bytes):
    def fetch(url, out, max_bytes, timeout):
        if ".cve.oval.xml.bz2" not in url:
            raise HTTPError(url, 404, "Not Found", None, None)
        out.write(bz2.compress(xml))

    return fetch


def feed_xml(known: int, unknown: int) -> bytes:
    """``known`` definitions in the current wording, then ``unknown`` in one nobody knows."""
    definitions = []
    for n in range(known + unknown):
        comment = KNOWN if n < known else UNKNOWN[n % len(UNKNOWN)]
        cve = f"CVE-2000-{n + 1:04d}"
        definitions.append(
            f'<definition class="vulnerability" id="oval:x:def:{n}"><metadata>'
            f"<title>{cve} on Ubuntu 24.04 LTS (noble) - low</title>"
            f'<reference source="CVE" ref_id="{cve}"/></metadata>'
            f'<criteria><criterion test_ref="oval:x:tst:{n}" comment="{comment}"/></criteria>'
            "</definition>"
        )
    body = "".join(definitions)
    xml = f'<oval_definitions xmlns="{NS}"><definitions>{body}</definitions></oval_definitions>'
    return xml.encode()


# --- the wordings ---------------------------------------------------------------------------


def test_source_package_form_with_every_status_phrase():
    found = entries()
    fixed = found[("CVE-2000-0101", "example-package")]
    assert (fixed.status, fixed.fixed_version) == ("released", "1.2.3-1ubuntu0.1")
    assert fixed.priority == "Medium" and fixed.note == "1.2.3-1ubuntu0.1"
    # "is affected and has been fixed" is a fix: "has been fixed" wins over "affected".
    curl = found[("CVE-2000-0101", "curl")]
    assert (curl.status, curl.fixed_version) == ("released", "8.5.0-2ubuntu10.5")
    assert found[("CVE-2000-0101", "vim")].status == "needs-triage"
    assert found[("CVE-2000-0101", "sudo")].status == "needed"


def test_pro_pocket_is_recorded_and_the_release_beats_it():
    found = entries()
    esm = found[("CVE-2000-0102", "example-package")]
    assert (esm.status, esm.fixed_version) == ("released", "2.0-1ubuntu0.1~esm1")
    assert oval_feed.stored_pocket(esm.note) == "esm-apps"
    # openssl: esm-infra says fixed first, the release itself says needed: the release wins.
    openssl = found[("CVE-2000-0102", "openssl")]
    assert openssl.status == "needed" and oval_feed.stored_pocket(openssl.note) is None


def test_quoted_kernel_form_emits_the_kernel_source_and_skips_the_running_check():
    found = entries()
    aws = found[("CVE-2000-0103", "linux-aws")]
    assert (aws.status, aws.fixed_version) == ("released", "6.8.0-1015.16")
    assert found[("CVE-2000-0103", "linux")].status == "needs-triage"
    # Without a note the version comes from the dpkginfo state of the kernel's test.
    assert found[("CVE-2000-0104", "linux-aws")].fixed_version == "6.8.0-1024.26"
    packages = {package for _, package in found}
    assert not any(" " in p or p.lower().startswith("is") for p in packages)


def test_the_old_wording_still_parses():
    found = entries()
    assert found[("CVE-2000-0105", "example-package")].fixed_version == "1.0-1ubuntu1"
    assert ("CVE-2000-0105", "zlib") not in found  # does not exist in this release
    assert {cve for cve, _ in found} == {f"CVE-2000-010{n}" for n in range(1, 6)}


CLASSIFY_CASES = [
    (KNOWN, ("example-package", "released", None)),
    (
        "example-package source package in esm-infra/noble, needs fixing.",
        ("example-package", "needed", "esm-infra"),
    ),
    (
        "'linux-aws' kernel in noble is affected and has been fixed (note: '6.8.0-1.1').",
        ("linux-aws", "released", None),
    ),
    (
        "'linux-aws-6.8' kernel in esm-infra/noble might be affected and may need fixing.",
        ("linux-aws-6.8", "needs-triage", "esm-infra"),
    ),
    (
        "example-package package in noble is affected and may need fixing.",
        ("example-package", "needs-triage", None),
    ),
    (  # the note is not searched for a status phrase
        "example-package source package in noble, needs fixing (note: 'has been fixed').",
        ("example-package", "needed", None),
    ),
]


@pytest.mark.parametrize("comment, expected", CLASSIFY_CASES)
def test_classify_each_wording(comment, expected):
    statement = oval_feed._classify(comment)
    assert (statement.package, statement.status, statement.pocket) == expected


@pytest.mark.parametrize(
    "comment",
    [
        "Is kernel 'linux-aws' running?",
        "Is kernel linux-aws running",
        "Ubuntu 24.04 LTS (noble) is installed.",
        "example-package source package in noble, has transcended.",
        "",
    ],
)
def test_comments_that_make_no_package_statement(comment):
    assert oval_feed._classify(comment) is None


# --- stored copy and resolver ---------------------------------------------------------------


def test_stored_forms_reach_the_resolver_with_pocket_and_kernel_path(db):
    feed = oval_feed.OvalFeed(db, fetcher=fetcher_of(FORMS_XML), now=lambda: START)
    state = feed.ensure("noble")
    assert state.usable and state.problem is None
    esm = feed.lookup("CVE-2000-0102", "noble")
    by_source = {e.source: e for e in esm.for_release("noble")}
    assert by_source["example-package"].is_pro and by_source["example-package"].status == "fixed"
    assert by_source["example-package"].distro == "esm-apps/noble"
    assert not by_source["openssl"].is_pro
    facts = parse_facts(facts_output())
    findings = cve_resolver.resolve_all(
        ["CVE-2000-0104"], lambda cve: feed.lookup(cve, "noble"), facts
    )
    (kernel,) = [f for f in findings if f.source == "linux-aws"]
    assert kernel.is_kernel and kernel.fixed_version == "6.8.0-1024.26"
    assert kernel.status != cve_resolver.METADATA_UNAVAILABLE


def test_unknown_pocket_is_still_pro(db):
    row = ("CVE-2000-0001", "example-package", "released", "1.0-1", "pocket:esm-x", None)
    db.add_oval_rows("noble", 1, [row])
    db.activate_oval_generation("noble", 1, START.isoformat(), 1)
    feed = oval_feed.OvalFeed(db, now=lambda: START)
    (entry,) = feed.lookup("CVE-2000-0001", "noble").for_release("noble")
    assert entry.is_pro


# --- format check ---------------------------------------------------------------------------


@pytest.mark.parametrize("known, unknown", [(2, 1), (1, 1), (3, 0)])
def test_a_feed_mostly_understood_is_accepted(known, unknown):
    assert len(list(oval_feed.parse_oval(io.BytesIO(feed_xml(known, unknown))))) == known


@pytest.mark.parametrize("known, unknown", [(1, 2), (0, 4)])
def test_a_feed_mostly_not_understood_means_the_parser_is_out_of_date(known, unknown):
    with pytest.raises(oval_feed.OvalFormatError, match="parser out of date"):
        list(oval_feed.parse_oval(io.BytesIO(feed_xml(known, unknown))))


def test_unrecognised_format_is_reported_as_such_not_as_a_corrupt_download(db):
    feed = oval_feed.OvalFeed(db, fetcher=fetcher_of(feed_xml(0, 4)), now=lambda: START)
    state = feed.ensure("noble")
    assert not state.usable
    assert state.problem.startswith(oval_feed.FORMAT_UNRECOGNISED)
    assert "0 of 4" in state.problem and "corrupt" not in state.message
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM oval_cve_packages").fetchone()[0] == 0


def test_unrecognised_format_keeps_the_previous_copy(db):
    clock = {"now": START}
    feed = oval_feed.OvalFeed(db, fetcher=fetcher_of(FORMS_XML), now=lambda: clock["now"])
    feed.ensure("noble")
    clock["now"] = START + timedelta(hours=48)
    feed.fetcher = fetcher_of(feed_xml(0, 4))
    state = feed.ensure("noble")
    assert state.usable and oval_feed.FORMAT_UNRECOGNISED in state.problem
    assert feed.lookup("CVE-2000-0101", "noble") is not None
