# Testing notes

## Local checks performed in the generation environment

The environment did not contain an Android SDK (`android.jar`) or a Gradle installation and had no network resolution to fetch them. A full Android Gradle build/APK could therefore not be run here. Do not assume the app source is compile-verified just because the core Java checks passed.

The following pure-Java classes were compiled locally with `javac`: `Hex`, `HkdfSha256`, `MessagePacket`, and `ReplayWindow`. `Argon2idKdf` was also compiled against an available Bouncy Castle jar. A local smoke test checked:

- HKDF-SHA-256 output matches RFC 5869 test case 1.
- A multibyte UTF-8 message encrypts/decrypts back to the original byte sequence.
- 87 plaintext bytes produce a 160-character Base64 packet; 88 bytes are rejected.
- Modifying ciphertext causes AES-GCM authentication failure.
- Directional derivations differ and reverse-direction decrypt is rejected.
- Replay window accepts an unseen in-window delayed packet and rejects duplicates and sufficiently old packets.

The Gradle/JUnit test source also includes packet round trips, fresh nonce behavior, tampering, wrong direction, ACK packet type, SMS size boundary, HKDF test vector, and replay-window tests. Those JUnit tests have not been run by Gradle in this environment.

## Acceptance checklist for Android Studio and two physical phones

- [ ] Gradle sync and debug build succeed with no missing dependencies.
- [ ] Install on Android 9 and a current Android version; grant SEND_SMS/RECEIVE_SMS and optional notification permission.
- [ ] Create a vault, restart the app, unlock, and verify no plaintext message file appears in app storage.
- [ ] Enter the emergency password; verify all app-owned contacts, keys, vault messages, pending packets, prefs, and DBs are removed and setup restarts cleanly.
- [ ] Attempt wrong normal passwords and verify delays at attempts 5, 10, 15, 20; reboot during each lockout and confirm behavior.
- [ ] Exchange a freshly generated 32-byte key using an out-of-band channel; confirm both phones use E.164 numbers consistently.
- [ ] Send short plain ASCII, accented text, non-Latin text, combining characters, and emoji; ensure the live meter is byte-aware and no message is split.
- [ ] Try exactly 87 UTF-8 bytes and 88 UTF-8 bytes; verify the UI and send-time segment guard.
- [ ] Capture the carrier/SMS body; verify it contains Base64 ciphertext only, not plaintext or key material.
- [ ] Before unlocking, inspect the private pending SQLite DB in a debug build: the candidate packet body should be AES-GCM ciphertext under the Android Keystore queue key, not a clear Base64 string. Verify emergency reset removes both the DB and queue-key alias.
- [ ] Modify one Base64-valid packet byte, send a malformed packet, send a packet from an unknown number, and try wrong-key traffic; none must be displayed as a trusted message.
- [ ] Deliver a valid later counter before an earlier one; both unseen counters within the 64-window should be accepted.
- [ ] Deliver exact duplicates and packets at least 64 behind the current highest; duplicates/stale packets must not create another message.
- [ ] Suppress the first ACK and retry the original packet; the receiver should resend the exact saved ACK without duplicate display.
- [ ] Force-stop/kill the process and reboot at points before send, after packet persistence, after receive persistence, and during ACK sending. Verify counters never reset and the app can recover safely.
- [ ] Check SMS provider/default SMS app/system notifications: ciphertext may be stored there, but notifications from Cipher SMS itself must not show plaintext.
- [ ] Repeat on different manufacturers/carriers, including sender IDs with country code and without it.

Do not use this version for critical or high-risk communications until these checks pass and the protocol/code have been independently reviewed.
