"""The findings register for booking-mobile's release APK: the single source of truth.

`status` drives tests/test_findings.py, the same way as in booking-pentest:
  open       reproduced: its test expects the weakness in the scanned APK
  accepted   the risk is accepted (with a reason): still reproduced
  fixed      remediated: its test expects it gone (the retest)

`severity` is this assessment's rating. MobSF's own rating is kept beside it,
because a scanner rates the pattern and not this app: the report says why
they differ.

REVIEWED lists MobSF items that were checked and are not findings. Every
high or warning item in a scan must be a finding or reviewed
(tests/test_triage.py), so a new issue in a later scan fails CI until
someone looks at it.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("High", "Medium", "Low")


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str  # this assessment's rating: High | Medium | Low
    mobsf: str  # MobSF's rating, or "not detected"
    masvs: str  # OWASP MASVS v2 control, or OWASP Mobile Top 10 (2024)
    mobsf_title: str  # text of the MobSF scorecard item it covers; "" if MobSF misses it
    status: str  # open | accepted | fixed
    fixed_in: str = ""
    accepted_because: str = ""

    @property
    def reproduced(self) -> bool:
        return self.status in ("open", "accepted")


FINDINGS = [
    Finding(
        id="MS-01",
        title="The release build is signed with the debug certificate",
        severity="Medium",
        mobsf="high",
        masvs="MASVS-RESILIENCE-2",
        mobsf_title="Application signed with debug certificate",
        status="open",
    ),
    Finding(
        id="MS-02",
        title="The release build allows plain HTTP to local addresses",
        severity="Medium",
        mobsf="high",
        masvs="MASVS-NETWORK-1",
        mobsf_title="Domain config is insecurely configured to permit clear text traffic",
        status="open",
    ),
    Finding(
        id="MS-03",
        title="A demo API key is compiled into the release build",
        severity="Low",
        mobsf="not detected",
        masvs="M1: Improper Credential Usage",
        mobsf_title="",
        status="open",
    ),
    Finding(
        id="MS-04",
        title="App data can be backed up",
        severity="Low",
        mobsf="warning",
        masvs="MASVS-STORAGE-2",
        mobsf_title="android:allowBackup",
        status="open",
    ),
    Finding(
        id="MS-05",
        title="The app installs on Android 7, which gets no security updates",
        severity="Low",
        mobsf="high",
        masvs="MASVS-CODE-1",
        mobsf_title="App can be installed on a vulnerable unpatched Android version",
        status="open",
    ),
]

# MobSF items checked by hand and found not to be issues in this app.
REVIEWED = {
    "ProfileInstallReceiver": (
        "AndroidX's profile installer receiver is exported but guarded by "
        "android.permission.DUMP, a signature|privileged permission: only the "
        "system and adb shell can hold it."
    ),
    "insecure Random Number Generator": (
        "The hits are in compiled AndroidX and Flutter embedding classes. The app's "
        "own code is Dart and never generates random values; nothing security "
        "relevant (keys, tokens) is generated on the device."
    ),
}

BY_ID = {f.id: f for f in FINDINGS}
