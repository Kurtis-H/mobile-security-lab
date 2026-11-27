"""Fixtures: the MobSF report and the APK it scanned.

MOBSF_REPORT  MobSF's JSON report (default results/mobsf.json)
APK           the scanned APK (default target/build/app/outputs/flutter-apk/app-release.apk)

Both come from CI's scan job. Without them the scan tests are skipped, unless
REQUIRE_SCAN=1 (set in CI), which makes a missing scan a failure.
"""

from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _need(path: Path) -> Path:
    if not path.exists():
        if os.environ.get("REQUIRE_SCAN") == "1":
            pytest.fail(f"{path} is missing, but REQUIRE_SCAN=1")
        pytest.skip(f"no scan here ({path} missing); CI runs these")
    return path


@pytest.fixture(scope="session")
def report() -> dict:
    path = Path(os.environ.get("MOBSF_REPORT", ROOT / "results" / "mobsf.json"))
    return json.loads(_need(path).read_text())


@pytest.fixture(scope="session")
def apk() -> zipfile.ZipFile:
    default = ROOT / "target" / "build" / "app" / "outputs" / "flutter-apk" / "app-release.apk"
    return zipfile.ZipFile(_need(Path(os.environ.get("APK", default))))


@pytest.fixture(scope="session")
def scorecard(report: dict) -> list[dict]:
    """MobSF's high and warning items: the ones that need a decision."""
    card = report.get("_scorecard", {})
    return [item for level in ("high", "warning") for item in card.get(level, [])]
