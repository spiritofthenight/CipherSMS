# Cipher SMS v1 protocol notes

This document records the current implementation choices. It is not a replacement for independent cryptographic review.

## Contact secret and directional keys

Each relationship uses a new random 32-byte shared secret, manually exchanged out of band and stored only inside each phone's password-encrypted vault. The secret is represented as 64 hexadecimal characters in the UI. Do not reuse it for a different contact.

For a packet from `senderE164` to `recipientE164`, derive a 32-byte AES key with HKDF-SHA-256:

- IKM: the 32-byte shared secret.
- HKDF salt: ASCII `CipherSMS-HKDF-SHA256-v1`.
- Info: UTF-8 `CipherSMS/v1/AES-256-GCM\0from=<sender E.164>\0to=<recipient E.164>`.
- Output: 32 bytes for AES-256.

The reverse direction derives a different key. E.164 numbers are validated and their exact canonical forms are part of the key context. Contact provisioning must use the same peer number on both phones.

## Packet encoding

The binary packet is Base64-encoded into an ordinary SMS text body. Base64 is an encoding only; it is not encryption.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 1 | High nibble: protocol version (`1`); low nibble: type (`0` text, `1` acknowledgment) |
| 1 | 4 | Counter, unsigned big-endian |
| 5 | 12 | Fresh cryptographically random GCM nonce |
| 17 | variable | AES-GCM ciphertext followed by its 16-byte tag |

The first five bytes are the AES-GCM AAD, concatenated with UTF-8 `CipherSMS/v1\0from=<sender E.164>\0to=<recipient E.164>`. The full header, direction context, nonce, ciphertext, and tag are therefore authenticated by the GCM operation; header/context are not encrypted. There is no separate Ed25519 signature in v1 because the carrier is the only attacker we are designing message authentication against, and it is assumed not to know the pairwise secret.

A text message's ciphertext length equals its UTF-8 plaintext byte length. The fixed overhead is 33 bytes. A 120-byte raw packet becomes 160 Base64 characters; therefore no more than 87 UTF-8 plaintext bytes fit in the current v1 format. The app enforces a 160-character hard limit and separately checks `SmsManager.divideMessage()` before sending.

## Packet types and acknowledgments

Type `0` contains UTF-8 text. Type `1` has exactly four plaintext bytes containing the counter of the text packet being acknowledged, as unsigned big-endian. ACK packets use the same directional key and the same directional counter stream as all other packets; they have their own fresh nonce. ACKs are encrypted/authenticated and are never acknowledged in return.

The receiver saves the authenticated incoming message packet, new receive-window state, and generated ACK packet/counter together in the encrypted vault before attempting to send the ACK. If the same accepted text packet is received again, the receiver can resend the exact stored ACK packet; it does not encrypt an ACK again under an existing counter. ACKs confirm application acceptance, not human reading. A carrier delivery report alone is not an app acknowledgment.

## Counters and replay protection

Each contact stores one outgoing 32-bit unsigned counter and one incoming replay window. Text and ACK packets share the corresponding direction's counter stream. A packet uses the current outgoing counter; the increment and exact encrypted packet are saved atomically before sending. The counter may not wrap. When the value space is exhausted, the relationship must be replaced through an explicit safe new-key setup; carrier errors never reset it.

The 64-packet replay window records the highest authenticated counter and a bitmap of the last 64 counter positions. A previously unseen packet in the window is accepted even if it arrives after a newer packet. A duplicate or a packet 64 or more behind the highest counter is rejected. The replay-window update and message/ACK state are committed in the same encrypted-vault update. If saving fails, the raw candidate remains queued for later processing.

## Receiver flow

1. Accept only one-segment Base64 candidates with the expected version/type and bounded packet size.
2. Queue candidate packet text and sender address in a bounded app-private SQLite database. The packet body is encrypted at rest with an app-specific Android Keystore AES-GCM key and the sender/timestamp are bound as AAD; do not attempt message decryption while the vault is locked.
3. When unlocked, normalize the sender number and find a configured contact; unknown senders remain queued up to the queue cap.
4. Derive the expected directional key, verify the AES-GCM tag, check UTF-8 for text packets and check the exact ACK payload size.
5. Evaluate replay state only after cryptographic authentication.
6. Persist accepted encrypted message packet + replay update (+ ACK packet/counter for text messages) atomically in the encrypted vault, then remove the pending candidate.
7. Delete authenticated failures, duplicate/stale packets, and malformed packets; never treat them as trusted content. A duplicate text can trigger resending the previously saved ACK.

## Storage format

The vault JSON contains contact keys, counters, replay state, encrypted packet records, and pending ACK packet records; it contains no message plaintext field. The JSON bytes are encrypted by AES-GCM with a fresh 12-byte nonce per save and an `AtomicFile` write. The separate incoming queue is encrypted at rest with an app-specific Android Keystore AES-GCM key, and emergency reset deletes that key. The vault key is derived from the normal password with Argon2id (16-byte random salt, 32 MiB memory, 3 passes, 1 lane, 32-byte output). The values are fixed by implementation version and should be benchmarked on low-end Android 9 devices before release.
