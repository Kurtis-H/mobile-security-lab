# Mobile security assessment: booking-mobile (Android)

| | |
|---|---|
| Version | 1.0 (initial assessment) |
| Date | 27 November 2026 |
| Prepared by | Kurtis H |
| Target | The release APK of [booking-mobile](https://github.com/Kurtis-H/booking-mobile), built from `main` with Flutter stable |
| Approach | Static analysis of the built APK with MobSF, plus manual review of the source and the APK |

## 1. Executive summary

The Android app was assessed as a user would install it: the release APK, built from source in CI and scanned with MobSF. **5 findings were raised: 0 High, 2 Medium and 3 Low.** One of them (MS-03) was found by hand, not by the scanner. Every finding is checked by an automated test against each new build, so the report stays true as the app changes.

The two Medium findings are about how the release build is made, not about the app's code. The release APK is signed with the debug certificate (MS-01), and it still allows plain HTTP to the emulator and localhost addresses used in development (MS-02). Both come from development settings that also apply to release builds.

The app's own code holds up well. The API key is kept in memory only, never written to storage or logs. Plain HTTP is refused everywhere except the development addresses. There are no trackers and no secrets MobSF can see, and the native libraries are built with the usual protections.

**Recommended priorities:**

1. Sign release builds with a dedicated release key, and never fall back to the debug key (MS-01).
2. Allow plain HTTP only in debug and profile builds (MS-02).
3. Leave the demo key out of release builds (MS-03), and turn off backups (MS-04).

## 2. Scope

| In scope | Version tested |
|---|---|
| booking-mobile release APK (`dev.kurtish.booking_mobile`), all ABIs | `main` on the test date, built by [`.github/workflows/scan.yml`](.github/workflows/scan.yml) |

**Out of scope:** the booking API and web app (assessed in [booking-pentest](https://github.com/Kurtis-H/booking-pentest)), iOS, dynamic analysis on a device, and reverse engineering beyond what the findings needed.

**Rules of engagement:** all analysis runs in GitHub Actions, in a fresh runner with MobSF in a throwaway container. The APK is built from source there and never installed on a personal device.

## 3. Methodology

- **Standard:** [OWASP MASVS v2](https://mas.owasp.org/MASVS/) controls, tested following the [OWASP MASTG](https://mas.owasp.org/MASTG/). Hard-coded credentials map to the [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/), which names them directly.
- **Static analysis:** [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) scans the release APK: manifest, certificate, network security configuration, compiled code, native libraries, secrets and trackers.
- **Manual review** of the Dart source, the Android project and the APK itself. MobSF reads Java and Kotlin, but a Flutter app's own code is Dart compiled into `libapp.so`, which most of its checks can't see.
- **Triage:** every high or warning item from MobSF is either a finding here or reviewed and explained (section 7). A test enforces this, so a new item in a later scan fails CI until it's triaged.
- **Severity:** this assessment's own rating (High, Medium or Low) for this app, with MobSF's rating beside it. Where they differ, the finding says why.

## 4. Findings summary

| ID | Finding | Severity | MobSF | MASVS | Status |
|---|---|---|---|---|---|
| MS-01 | The release build is signed with the debug certificate | Medium | high | MASVS-RESILIENCE-2 | open |
| MS-02 | The release build allows plain HTTP to local addresses | Medium | high | MASVS-NETWORK-1 | open |
| MS-03 | A demo API key is compiled into the release build | Low | not detected | M1: Improper Credential Usage | open |
| MS-04 | App data can be backed up | Low | warning | MASVS-STORAGE-2 | open |
| MS-05 | The app installs on Android 7, which gets no security updates | Low | high | MASVS-CODE-1 | open |

## 5. Findings

### MS-01: The release build is signed with the debug certificate

**Medium** (MobSF: high) · MASVS-RESILIENCE-2 · `android/app/build.gradle.kts`

**Description.** The release build type uses `signingConfigs.getByName("debug")`, Flutter's template default. Every release APK is signed with whatever debug key the building machine has.

**Evidence.** MobSF: "Application signed with debug certificate". The certificate subject is `CN=Android Debug`.

**Impact.** Debug keys have a well-known password and are created per machine, so builds from different machines (every CI runner) carry different signatures and can't update each other. Google Play rejects debug-signed apps. Anyone who copies a developer's debug keystore can sign an "update" Android will accept. Rated Medium rather than High because the app isn't distributed yet.

**Remediation.** Sign release builds with a dedicated key read from `key.properties`, which stays out of git, and fail the build when it's missing instead of falling back to debug.

### MS-02: The release build allows plain HTTP to local addresses

**Medium** (MobSF: high) · MASVS-NETWORK-1 · `android/app/src/main/res/xml/network_security_config.xml`

**Description.** Plain HTTP is blocked by default, but a domain config allows it to `10.0.2.2`, `localhost` and `127.0.0.1`. That's needed to reach a local API from the emulator during development, but the same file is used by release builds. The app's default API address is also `http://10.0.2.2:8000`.

**Evidence.** MobSF's network security analysis: cleartext permitted to the three addresses.

**Impact.** A release build made without setting `API_URL` sends the buyer's API key over plain HTTP. On a real device, `10.0.2.2` is just an address on the network, so anyone on the same network who answers at that address gets the key. Another app on the device listening on `localhost` could receive it the same way. Rated Medium because it needs a misconfigured build, but the failure is silent and leaks a credential.

**Remediation.** Keep the cleartext exception in the debug and profile builds only, so a release build refuses plain HTTP everywhere and fails closed if it's pointed at an HTTP address.

### MS-03: A demo API key is compiled into the release build

**Low** (MobSF: not detected) · M1: Improper Credential Usage · `lib/session.dart`

**Description.** `Session.demoKey = 'key-user-1'` powers a "use the demo account" button on the sign-in screen, and it ships in release builds.

**Evidence.** The string `key-user-1` is in `libapp.so` for every ABI in the release APK. MobSF reports no secrets: it doesn't read the compiled Dart.

**Impact.** Anyone with the APK gets a working key for a real account. Here it's public test data (booking-pentest's BP-01 already notes the keys are predictable), so the impact is Low. In a real app, the same pattern would ship a shared credential to every user.

**Remediation.** Include the demo key only in non-release builds, using a compile-time constant so the release compiler drops the string entirely.

### MS-04: App data can be backed up

**Low** (MobSF: warning) · MASVS-STORAGE-2 · `android/app/src/main/AndroidManifest.xml`

**Description.** The manifest doesn't set `android:allowBackup`, so it defaults to `true`, and the app's data can be copied off the device with adb backup or cloud backup.

**Evidence.** MobSF: "Application Data can be Backed up [android:allowBackup] flag is missing."

**Impact.** Low today: the app keeps the API key in memory only and stores nothing sensitive. The setting matters the day someone adds "remember me", which would quietly put the key into backups.

**Remediation.** Set `android:allowBackup="false"` and `android:fullBackupContent="false"`.

### MS-05: The app installs on Android 7, which gets no security updates

**Low** (MobSF: high) · MASVS-CODE-1 · `android/app/build.gradle.kts`

**Description.** `minSdk` is Flutter's default, 24 (Android 7.0). Versions before Android 10 no longer get security updates.

**Evidence.** The APK's `minSdk` is 24.

**Impact.** Users on old devices run the app on an operating system with known, unpatched vulnerabilities, which the app can't defend against. Rated Low rather than MobSF's High: the app holds no data at rest, and its only secret lives in memory for the session.

**Remediation.** Raise `minSdk` to 29 (Android 10), or accept the risk for wider reach and revisit as old versions decline.

## 6. What's done well

- **No credential at rest.** The API key lives in memory for the session only. It isn't written to shared preferences, files or logs.
- **HTTPS by default.** The network security config blocks plain HTTP for every domain except the development addresses (see MS-02).
- **No secrets or trackers** found by MobSF. The only packages are Flutter's own `material_ui` (verified publisher flutter.dev) and `http`, with exact versions locked in `pubspec.lock`. `material_ui` was declared as `any`; the lock file kept builds reproducible, but the constraint is tightened in the fix.
- **One permission:** `INTERNET`.
- **Native libraries** have the NX bit set (no executable data pages).

## 7. Scanner items reviewed, not findings

| MobSF item | Why it isn't a finding |
|---|---|
| `ProfileInstallReceiver` exported, protected by `android.permission.DUMP` | AndroidX's profile installer. `DUMP` is a signature\|privileged permission, so only the system and adb shell can send to it. |
| "The App uses an insecure Random Number Generator" | The hits are compiled AndroidX and Flutter embedding classes. The app's own code is Dart and never generates random values, and nothing security relevant is generated on the device. |
| Logging and clipboard (info) | The same: library code. The app's Dart code doesn't log and doesn't copy to the clipboard. |

## Appendix A: Reproducing the findings

CI builds booking-mobile's release APK from `main`, scans it with MobSF (image pinned by digest), then runs `tests/`. A finding marked open or accepted must still be present, and one marked fixed must not. Every high or warning item must be triaged. See the [README](README.md).
