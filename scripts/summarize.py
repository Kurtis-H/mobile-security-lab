"""Print the parts of a MobSF JSON report that matter, for the job log.

    python scripts/summarize.py results/mobsf.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def items(section: object) -> list[tuple[str, dict]]:
    """MobSF sections are either {name: finding} or [finding, ...]."""
    if isinstance(section, dict):
        return [(k, v) for k, v in section.items() if isinstance(v, dict)]
    if isinstance(section, list):
        return [(str(i), v) for i, v in enumerate(section) if isinstance(v, dict)]
    return []


def severity(finding: dict) -> str:
    meta = finding.get("metadata", finding)
    return str(meta.get("severity") or meta.get("stat") or "").lower()


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text())
    print("== App:", report.get("app_name"), report.get("package_name"), report.get("version_name"))
    print("   min/target SDK:", report.get("min_sdk"), report.get("target_sdk"))
    print("== Scorecard:", json.dumps(report.get("_scorecard"), indent=1)[:4000])
    print("== Security score:", report.get("appsec", {}).get("security_score"))
    cert = report.get("certificate_analysis", {})
    print("== Certificate:", json.dumps(cert.get("certificate_findings"), indent=1)[:1500])
    print("== Manifest findings:")
    for _, f in items(report.get("manifest_analysis", {}).get("manifest_findings", [])):
        print(f"  [{severity(f)}] {f.get('title') or f.get('rule')}: {str(f.get('description'))[:160]}")
    print("== Network security:")
    for _, f in items(report.get("network_security", {}).get("network_findings", [])):
        print(f"  [{severity(f)}] {f.get('scope')}: {str(f.get('description'))[:160]}")
    print("== Code analysis:")
    for name, f in items(report.get("code_analysis", {}).get("findings", report.get("code_analysis", {}))):
        files = list((f.get("files") or {}).keys())[:3]
        print(f"  [{severity(f)}] {name}: {str(f.get('metadata', {}).get('description'))[:140]} {files}")
    print("== Binary analysis:")
    for name, f in items(report.get("binary_analysis", {})):
        print(f"  {name}: {json.dumps(f)[:200]}")
    print("== Secrets:", report.get("secrets"))
    print("== Permissions:")
    for name, f in items(report.get("permissions", {})):
        print(f"  [{f.get('status')}] {name}")
    print("== Trackers:", report.get("trackers", {}).get("detected_trackers"))
    print("== Top-level keys:", sorted(report))


if __name__ == "__main__":
    main()
