# Security assumptions and limitations

## Threat model

Cipher SMS v1 assumes a non-compromised Android device and OS. The mobile carrier/network may observe SMS metadata and may alter, forge, replay, duplicate, delay, reorder, or drop SMS bodies. The attacker does not know the pairwise shared secret. The app aims to keep message contents confidential and reject carrier-forged/tampered packets.

Availability is not guaranteed: a carrier can suppress all messages. Caller/recipient identity, timestamps, traffic volume, and the presence of encrypted communication are not hidden.

## Cryptography

- AES-256-GCM for confidentiality and integrity/authentication with a full 128-bit tag.
- Fresh random 96-bit nonce for each new packet. Retry must send the identical saved packet; it must never re-encrypt with the same nonce/counter combination.
- HKDF-SHA-256 derives direction-specific AES keys from per-contact 32-byte secrets; the derivation implementation clears intermediate HMAC input buffers after use.
- Argon2id protects the password vault; AES-GCM encrypts the vault file.
- No per-message public-key signature is used. Because both endpoints know the symmetric relationship secret, either endpoint can generate a packet that validates for that relationship. This is intentional for the stated carrier-only message-forgery threat model; there is no non-repudiation.

## Local vault and plaintext

App-owned message records contain encrypted packet strings only. Incoming SMS candidate packets are queued in a private SQLite DB until unlocked; the queue contains ciphertext packet text and sender/received-time metadata. Message text is decrypted for display after unlock and should not be persisted to logs or temporary files. Java/Android cannot guarantee immediate erasure of every plaintext copy from RAM, and the app cannot control OS screenshots outside of the screen-capture flag, keyboards, rooted devices, memory dumps, or external system behavior.

The vault password is not stored. The emergency password is represented by a verifier derived with Argon2id and HMAC; entering it through the unlock screen starts the destructive reset. Argon2id's 32 MiB/3-pass parameters are an initial compromise for supported older devices, not a universally optimal release setting; measure unlock time and review parameters before release. Weak human passwords can still be guessed offline if the app files are extracted.

## Lockout and emergency reset

Failed normal-password attempts use persistent throttling: 1–4 no delay, 5–9 one minute after the fifth failure, 10–14 two minutes after the tenth, 15–19 five minutes after the fifteenth, and 20+ one hour. A successful normal unlock resets consecutive failures. The emergency password is checked even while normal unlocking is throttled. Lockout persistence depends on Android's boot counter and shared preferences; a compromised OS or rollback of app data can defeat such controls.

Emergency reset best-effort deletes app-private data, databases, shared preferences, caches and app-specific external directories, and destroys in-memory vault keys. It is not a forensic-grade flash wipe and cannot erase SMS provider history, other apps' copies, screenshots, exported files, or external backups. If local verifier files are corrupted/missing, automatic emergency-password recognition may be unavailable; preserve no backups and do not rely on reset as a substitute for safe device handling.

## Messaging details

A 64-counter replay window permits valid unseen packets to arrive out of order. Duplicates and packets 64 or more behind the highest authenticated counter are rejected. Receive state is committed with accepted messages in an atomic encrypted-vault write. Outgoing encrypted packets and incremented counters are persisted before send. If storage or process state is uncertain, the app must fail closed rather than reset keys/counters.

Only one SMS segment is allowed. The composer calculates UTF-8 bytes plus protocol/Base64 overhead; `SmsManager.divideMessage()` is checked at send time. The limit is not equivalent to a fixed visible-character count for Unicode text. There is no automatic multipart assembly.

## Platform and release caveats

- This source project was not built into an APK in the generation environment and has not been tested on physical devices or carriers.
- SMS receiver behavior, sender-number formatting, `SmsManager` segment accounting, notifications, runtime permission flows, process death, Doze, reboot, and Android vendor variations all require real-device tests.
- The app is not the default SMS app. Android and the default SMS app may store the encrypted Base64 SMS body in system SMS history.
- Current code is an experimental initial implementation. Before sensitive use, it needs full compilation, automated and integration tests, protocol review, threat-model review, and an independent security audit.
