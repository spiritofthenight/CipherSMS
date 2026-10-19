# Cipher SMS (experimental Android project)

Cipher SMS is an early Java Android Studio implementation of encrypted one-part SMS messaging. It targets Android 9 (API 28) and later. **It has not been independently audited and must not yet be relied on for high-risk communications.**

## What is implemented

- Local vault protected by Argon2id and AES-GCM-encrypted storage.
- Separate normal and emergency passwords. Failed normal-password attempts trigger escalating delays; the emergency password initiates app-owned-data deletion and fresh setup.
- Manually exchanged 32-byte per-contact secrets, shown as 64 hexadecimal characters. Fresh secrets must be used for different contacts/relationships.
- Direction-specific AES-256-GCM keys derived from the shared secret using HKDF-SHA-256 and the sender/recipient E.164 numbers.
- A fresh random 12-byte nonce and full 16-byte GCM authentication tag for each new packet.
- Base64 text SMS transport with a one-segment send-time check. The composer counts UTF-8 bytes live and blocks input that would exceed the protocol's 87-byte plaintext ceiling.
- A 4-byte unsigned per-direction counter and 64-packet replay window. Valid unseen packets within the window can arrive out of order; duplicates and packets at least 64 counters behind the highest accepted counter are rejected.
- Encrypted app-level acknowledgments, exact-packet retry, and status text that distinguishes Android/carrier status from acceptance by the recipient app.
- An SMS broadcast receiver that queues incoming candidates while locked; the queue body is encrypted again at rest with an app-specific Android Keystore AES-GCM key, so even unauthenticated Base64 candidates are not saved in clear. No message plaintext is stored in the app database or vault.
- Backup/data-transfer exclusions, screen-capture blocking, generic incoming notifications, and bounded message/pending-packet queues.
- Unit tests for packet round trips, direction separation, tamper rejection, encoded size boundary, HKDF RFC 5869 test vector, and replay-window behavior.

## Build in Android Studio

1. Install a current Android Studio release with Android SDK Platform 36 and a Java 17-compatible Gradle runtime.
2. Open the `CipherSMS` directory as an existing Gradle project. This source package does not include Gradle Wrapper scripts because the build tools were unavailable in the generation environment. If Android Studio needs a wrapper, run `gradle wrapper --gradle-version 8.13` from the project root on a machine with Gradle 8.13 installed, then reopen/sync the project.
3. Allow Android Studio/Gradle to resolve the Android Gradle Plugin and Maven dependencies. This project uses Android Gradle Plugin 8.13.2, Gradle 8.13, Bouncy Castle 1.86, libphonenumber 9.0.41, and JUnit 4.13.2.
4. Build and run the `app` configuration on an Android 9+ device with SMS hardware/SIM service.
5. Grant SMS permissions. Use two test phones/SIMs to exercise first-time setup, key entry, message exchange, acknowledgments, retries, lockout, emergency reset, process death, reboot, and messages arriving out of order.

This delivery does not include a Gradle wrapper because the generation environment had neither Gradle nor the Android SDK and could not reach the network to obtain the wrapper distribution. The Android project has therefore **not** been compiled as a full APK here. The pure-Java cryptographic core was compiled and smoke-tested locally; see `TESTING.md`.

## First-time setup and contact exchange

1. On each phone, enter that phone's own number in international E.164 format (`+` followed by country code and number), a strong vault password, and a different emergency password. There is no password recovery.
2. On one phone, open **Add contact**, enter the other person's name and number in E.164 format, tap **Generate key**, and securely exchange the displayed 64-character key through a separate trusted channel. Avoid clipboard history or cloud-synced notes when exchanging key material.
3. Add the contact on the other phone using the *same* key but the other person's own phone number as the contact number. Use a new random key for every relationship. Never send the secret key by SMS.
4. Grant SMS permissions on both phones and send a short test message in each direction.

The phone numbers are bound into directional key derivation and message authentication. Use canonical international numbers on both sides. Some networks report sender addresses in unexpected formats; test with the actual carriers you intend to use.

## SMS length

The wire packet has 33 bytes of fixed overhead: 1 version/type byte, a 4-byte counter, a 12-byte nonce, and a 16-byte AES-GCM tag. The Base64 output is limited to 160 GSM-7 characters, allowing at most 120 raw bytes and therefore up to **87 UTF-8 plaintext bytes**. Text using non-ASCII characters can reach the byte limit with fewer visible characters. Before sending, the app also asks Android to divide the Base64 body and refuses to send unless Android reports exactly one segment. It never silently splits a message.

## Acknowledgments

A recipient app sends an encrypted acknowledgment after it has authenticated a text packet and committed the message and replay state to the encrypted vault. This acknowledgment means the recipient **app accepted the message**, not that a human read it. A carrier may suppress the acknowledgment; in that case the sender can resend the exact original packet. Duplicate receiving apps should not show the message twice.

## Important platform limitations

- This is an early implementation, not a finished or audited secure messenger. Test the exact Android versions, manufacturers, SIMs, and carriers you plan to support.
- Android's SMS provider/default SMS app may store or display the Base64 ciphertext. This app does not control system SMS history, screenshots, exports, other apps, or backups outside its control.
- The emergency reset deletes app-private data and keys on a best-effort basis. Flash storage may retain physical remnants, and the app cannot erase system-owned SMS copies or third-party data.
- The app is not the default SMS app and relies on SMS permissions and system broadcasts. Store distribution may impose additional restrictions on SMS permissions; this project is intended initially for controlled testing/sideloading.
- SMS metadata is not hidden. A carrier can always block messages, delay them indefinitely, or observe sender, recipient, timing, and traffic volume.
- A trusted contact who knows the pairwise symmetric secret can create a valid packet for that relationship. This design authenticates against a carrier that does not know the secret; it does not provide per-message non-repudiation against the other endpoint.

## License status
MIT

## Files

- `PROTOCOL.md` — wire format, key derivation, counters, replay window, acknowledgment behavior.
- `SECURITY.md` — threat model, password vault, reset guarantees, and limitations.
- `TESTING.md` — local core test results and a two-device acceptance checklist.
