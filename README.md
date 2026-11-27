# mobile-security-lab

A mobile security assessment of [booking-mobile](https://github.com/Kurtis-H/booking-mobile), the Flutter Android app in this portfolio. The [report](REPORT.md) is checked by CI against every new build of the app.

CI builds the **release APK** from booking-mobile's `main`, the way a user would get it. It then scans the APK with [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) and checks each finding against the result, with findings mapped to [OWASP MASVS](https://mas.owasp.org/MASVS/).

## Why it's built this way

A scanner's output isn't an assessment. MobSF rated three items "high" in this app. On review, none of them is High for this app, two of its warnings aren't issues at all, and the scanner missed something a manual check found. This repo keeps both the scanner and the judgment:

- **Every finding is a test.** [`tests/test_findings.py`](tests/test_findings.py) checks each finding in the scanned APK. A finding marked open or accepted must still be present. One marked fixed must not be, and that is the retest.
- **Every scanner item is triaged.** [`tests/test_triage.py`](tests/test_triage.py) fails if MobSF reports a high or warning item that isn't a finding or a reviewed false positive with a written reason. A new issue in a later build of the app fails CI until someone looks at it.
- **The scanner's blind spot is covered.** A Flutter app's own code is Dart, compiled into `libapp.so`, which MobSF's code and secret checks don't read. MS-03 (a demo key in the release build) is found by reading the APK directly.
- **The report can't drift.** [`tests/test_report.py`](tests/test_report.py) checks REPORT.md against [`findings.py`](findings.py): every finding, rating, MASVS control and status, and an explanation for every reviewed item.
- **The target is tested at `main`,** on every push and weekly, so a change in the app that reopens a finding, or fixes one, fails this repo's CI until the report is updated.

## Status

Version 1.1 of the [report](REPORT.md) is the retest: 4 of 5 findings fixed and verified in a new release build (MS-01 to MS-04), and 1 accepted with its reason (MS-05).

The live status of every finding is on the [quality dashboard](https://kurtis-h.github.io/quality-dashboard/), read from this repo's `findings.py`.

## Contained by design

Nothing here runs on a personal machine or touches a real device. The APK is built from source in a fresh GitHub Actions runner. MobSF runs there in a throwaway container, pinned by image digest. The release signing key is generated for each run and discarded with the runner, so there is no secret to store.

## Layout

```
findings.py        the findings register: severity, MobSF's rating, MASVS control, status;
                   plus REVIEWED, the scanner items checked and found not to be issues
scripts/
  mobsf_scan.py    uploads the APK to MobSF's REST API, runs the scan, saves the JSON report
  summarize.py     prints the parts of the report that matter, for the job log
tests/
  test_findings.py each finding, checked in the scanned APK
  test_triage.py   every high or warning item from MobSF is triaged
  test_report.py   REPORT.md agrees with the register
REPORT.md          the assessment
```

## Run it

CI is the intended way: push, or run the workflow by hand. Its summary shows the evidence for each finding, and the full MobSF report is uploaded as an artifact.

Locally, the report test needs no scan:

```bash
pip install --require-hashes -r requirements.txt
python -m pytest tests/test_report.py
```

The scan tests read `results/mobsf.json` and the APK (`MOBSF_REPORT` and `APK` override the paths), and skip when they're missing. CI sets `REQUIRE_SCAN=1` so a missing scan fails instead.

## Related

- [booking-pentest](https://github.com/Kurtis-H/booking-pentest): the same approach for the booking API and web app.
- [booking-mobile](https://github.com/Kurtis-H/booking-mobile): the app under test.
