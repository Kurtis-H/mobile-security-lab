"""Each finding, checked against the scanned release APK.

A finding marked open or accepted must still be present; one marked fixed must
not (the retest). The evidence goes to results/evidence.md for the job summary.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from findings import BY_ID

RESULTS = Path(__file__).resolve().parents[1] / "results"
_evidence: list[str] = []


@pytest.fixture(scope="session", autouse=True)
def write_evidence():
    yield
    if _evidence:
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / "evidence.md").write_text(
            "| Finding | Status | Present | Evidence |\n|---|---|---|---|\n" + "".join(_evidence)
        )


def verdict(finding_id: str, present: bool, evidence: str) -> None:
    f = BY_ID[finding_id]
    _evidence.append(f"| {f.id} {f.title} | {f.status} | {'yes' if present else 'no'} | {evidence} |\n")
    if f.reproduced:
        assert present, f"{f.id} is {f.status}, so it should be present, but isn't: {evidence}"
    else:
        assert not present, f"{f.id} is marked fixed, but is still present: {evidence}"


def flagged(scorecard: list[dict], text: str) -> list[str]:
    return [item["title"] for item in scorecard if text in item["title"]]


def test_ms01_release_signed_with_debug_certificate(report: dict, scorecard: list[dict]) -> None:
    hits = flagged(scorecard, BY_ID["MS-01"].mobsf_title)
    subject = str(report.get("certificate_analysis", {}).get("certificate_info", ""))
    debug_subject = "CN=Android Debug" in subject
    verdict(
        "MS-01",
        bool(hits) or debug_subject,
        f"MobSF: {'flagged' if hits else 'not flagged'}; certificate subject is "
        f"{'the Android debug certificate' if debug_subject else 'not the debug certificate'}",
    )


def test_ms02_release_allows_cleartext(report: dict) -> None:
    findings = report.get("network_security", {}).get("network_findings", [])
    cleartext = [
        f
        for f in findings
        if "permit clear text" in str(f.get("description")) and f.get("severity") == "high"
    ]
    scopes = sorted({d for f in cleartext for d in f.get("scope", [])})
    verdict(
        "MS-02",
        bool(cleartext),
        f"cleartext permitted to: {', '.join(scopes)}" if scopes else "no cleartext domain config",
    )


def test_ms03_demo_key_compiled_in(apk: zipfile.ZipFile) -> None:
    # MobSF can't see this: Dart is compiled ahead of time into libapp.so, which
    # its secret scan doesn't read. The bytes are there all the same.
    libs = [n for n in apk.namelist() if n.endswith("/libapp.so")]
    assert libs, "no libapp.so in the APK: not a Flutter release build?"
    with_key = [n for n in libs if b"key-user-1" in apk.read(n)]
    verdict(
        "MS-03",
        bool(with_key),
        f"`key-user-1` found in {len(with_key)} of {len(libs)} libapp.so builds",
    )


def test_ms04_app_data_can_be_backed_up(scorecard: list[dict]) -> None:
    hits = flagged(scorecard, BY_ID["MS-04"].mobsf_title)
    verdict("MS-04", bool(hits), hits[0] if hits else "allowBackup is set to false")


def test_ms05_installs_on_unsupported_android(report: dict) -> None:
    min_sdk = int(report["min_sdk"])
    # Android 10 (API 29) is the oldest version still getting security updates
    # when MobSF's rule was written.
    verdict("MS-05", min_sdk < 29, f"minSdk {min_sdk}")


@pytest.mark.parametrize("key", ["secrets", "trackers"])
def test_nothing_found_where_nothing_should_be(report: dict, key: str) -> None:
    """Controls: no hard-coded secrets MobSF can see, and no trackers."""
    if key == "secrets":
        # Assert on the count only, so a failure never prints a secret to the public log.
        found = len(report.get("secrets") or [])
        assert found == 0, f"MobSF found {found} possible secrets: see the report artifact"
    else:
        assert not report.get("trackers", {}).get("detected_trackers")
