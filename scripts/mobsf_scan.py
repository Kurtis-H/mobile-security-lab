"""Upload an APK to a running MobSF, scan it, and save the JSON report.

    python scripts/mobsf_scan.py app.apk --out results/mobsf.json

MOBSF_URL (default http://localhost:8000) and MOBSF_API_KEY come from the
environment. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

URL = os.environ.get("MOBSF_URL", "http://localhost:8000").rstrip("/")
KEY = os.environ["MOBSF_API_KEY"]


def call(path: str, data: bytes, content_type: str, timeout: float = 900) -> dict:
    request = urllib.request.Request(  # noqa: S310 - a fixed local MobSF URL
        f"{URL}{path}",
        data=data,
        headers={"Authorization": KEY, "X-Mobsf-Api-Key": KEY, "Content-Type": content_type},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.load(response)


def form(path: str, **fields: str) -> dict:
    return call(path, urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded")


def upload(apk: Path) -> dict:
    boundary = uuid.uuid4().hex
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{apk.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + apk.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    return call("/api/v1/upload", body, f"multipart/form-data; boundary={boundary}")


def wait_until_up(seconds: int = 300) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            urllib.request.urlopen(f"{URL}/api_docs", timeout=5)  # noqa: S310
            return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--out", type=Path, default=Path("results/mobsf.json"))
    args = parser.parse_args()

    wait_until_up()
    uploaded = upload(args.apk)
    print(f"uploaded {uploaded['file_name']} ({uploaded['hash']})")
    form("/api/v1/scan", hash=uploaded["hash"], scan_type=uploaded["scan_type"], file_name=uploaded["file_name"])
    report = form("/api/v1/report_json", hash=uploaded["hash"])
    try:
        report["_scorecard"] = form("/api/v1/scorecard", hash=uploaded["hash"])
    except OSError as error:  # older MobSF versions have no scorecard endpoint
        report["_scorecard"] = {"error": str(error)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(f"report written to {args.out}")


if __name__ == "__main__":
    main()
