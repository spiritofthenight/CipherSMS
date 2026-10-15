package org.ciphersms.app.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * CipherSMS v1 wire format before Base64:
 *   version/type(1: high nibble version, low nibble kind) || counter(4, unsigned big-endian)
 *   || nonce(12) || ciphertext || GCM tag(16).
 * The 5-byte header and sender/recipient context are authenticated as GCM AAD.
 */
public final class MessagePacket {
    public static final int VERSION = 1;
    public static final int TYPE_MESSAGE = 0;
    public static final int TYPE_ACK = 1;
    public static final int VERSION_BYTES = 1;
    public static final int COUNTER_BYTES = 4;
    public static final int HEADER_BYTES = VERSION_BYTES + COUNTER_BYTES;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;
    public static final int FIXED_OVERHEAD_BYTES = HEADER_BYTES + NONCE_BYTES + TAG_BYTES; // 33
    public static final int MAX_SMS_TEXT_CHARS = 160;
    public static final int MAX_RAW_PACKET_BYTES = 120;
    public static final long MAX_COUNTER = 0xffff_ffffL;
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] HKDF_SALT = "CipherSMS-HKDF-SHA256-v1".getBytes(StandardCharsets.US_ASCII);

    private MessagePacket() { }

    public static String encrypt(byte[] sharedSecret, String senderE164, String recipientE164,
                                 long counter, byte[] plaintext) throws GeneralSecurityException {
        return encryptTyped(sharedSecret, senderE164, recipientE164, TYPE_MESSAGE, counter, plaintext);
    }

    public static String encryptTyped(byte[] sharedSecret, String senderE164, String recipientE164,
                                      int type, long counter, byte[] plaintext) throws GeneralSecurityException {
        validateSecret(sharedSecret);
        if (type != TYPE_MESSAGE && type != TYPE_ACK) throw new IllegalArgumentException("Unknown packet type");
        validateNumber(senderE164);
        validateNumber(recipientE164);
        if (senderE164.equals(recipientE164)) throw new IllegalArgumentException("Sender and recipient must differ");
        if (counter < 0 || counter > MAX_COUNTER) throw new IllegalArgumentException("Counter exhausted");
        if (plaintext == null) throw new IllegalArgumentException("Plaintext is required");
        if (!plaintextFitsSingleSms(plaintext.length)) throw new IllegalArgumentException("Message exceeds one SMS");

        // One byte packs protocol version in the high nibble and packet type in the low nibble.
        byte versionAndType = (byte) ((VERSION << 4) | type);
        byte[] header = ByteBuffer.allocate(HEADER_BYTES).put(versionAndType).putInt((int) counter).array();
        byte[] nonce = new byte[NONCE_BYTES];
        RNG.nextBytes(nonce);
        byte[] key = deriveDirectionalKey(sharedSecret, senderE164, recipientE164);
        byte[] aad = makeAad(header, senderE164, recipientE164);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            byte[] ciphertextAndTag = cipher.doFinal(plaintext);
            ByteArrayOutputStream packet = new ByteArrayOutputStream(FIXED_OVERHEAD_BYTES + plaintext.length);
            packet.write(header, 0, header.length);
            packet.write(nonce, 0, nonce.length);
            packet.write(ciphertextAndTag, 0, ciphertextAndTag.length);
            byte[] raw = packet.toByteArray();
            if (raw.length > MAX_RAW_PACKET_BYTES) throw new IllegalArgumentException("Packet exceeds single-SMS limit");
            return Base64.getEncoder().encodeToString(raw);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(aad, (byte) 0);
        }
    }

    public static Decoded decrypt(byte[] sharedSecret, String senderE164, String recipientE164,
                                  String encodedPacket) throws GeneralSecurityException {
        validateSecret(sharedSecret);
        validateNumber(senderE164);
        validateNumber(recipientE164);
        if (senderE164.equals(recipientE164)) throw new IllegalArgumentException("Sender and recipient must differ");
        byte[] raw = decodeAndValidate(encodedPacket);
        byte[] header = Arrays.copyOfRange(raw, 0, HEADER_BYTES);
        int versionAndType = raw[0] & 0xff;
        int type = versionAndType & 0x0f;
        long counter = Integer.toUnsignedLong(ByteBuffer.wrap(header, VERSION_BYTES, COUNTER_BYTES).getInt());
        byte[] nonce = Arrays.copyOfRange(raw, HEADER_BYTES, HEADER_BYTES + NONCE_BYTES);
        byte[] ciphertextAndTag = Arrays.copyOfRange(raw, HEADER_BYTES + NONCE_BYTES, raw.length);
        byte[] key = deriveDirectionalKey(sharedSecret, senderE164, recipientE164);
        byte[] aad = makeAad(header, senderE164, recipientE164);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            byte[] plaintext = cipher.doFinal(ciphertextAndTag); // rejects tampering with AEADBadTagException
            return new Decoded(counter, type, plaintext);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(aad, (byte) 0);
            Arrays.fill(ciphertextAndTag, (byte) 0);
            Arrays.fill(raw, (byte) 0);
        }
    }

    public static boolean isTransportCandidate(String body) {
        if (body == null || body.isEmpty() || body.length() > MAX_SMS_TEXT_CHARS || (body.length() & 3) != 0) return false;
        if (!body.matches("[A-Za-z0-9+/]+={0,2}")) return false;
        try {
            byte[] raw = Base64.getDecoder().decode(body);
            boolean okay = raw.length >= FIXED_OVERHEAD_BYTES && raw.length <= MAX_RAW_PACKET_BYTES
                    && ((raw[0] & 0xff) >>> 4) == VERSION
                    && (((raw[0] & 0x0f) == TYPE_MESSAGE) || ((raw[0] & 0x0f) == TYPE_ACK))
                    && Base64.getEncoder().encodeToString(raw).equals(body);
            Arrays.fill(raw, (byte) 0);
            return okay;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public static byte[] decodeAndValidate(String encodedPacket) {
        if (!isTransportCandidate(encodedPacket)) throw new IllegalArgumentException("Invalid CipherSMS packet format");
        byte[] raw = Base64.getDecoder().decode(encodedPacket);
        if (raw.length < FIXED_OVERHEAD_BYTES || raw.length > MAX_RAW_PACKET_BYTES) {
            Arrays.fill(raw, (byte) 0);
            throw new IllegalArgumentException("Invalid packet size");
        }
        return raw;
    }

    public static int utf8Bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    public static int encodedLengthForPlaintextBytes(int plaintextBytes) {
        if (plaintextBytes < 0) throw new IllegalArgumentException("Negative plaintext length");
        int rawBytes = FIXED_OVERHEAD_BYTES + plaintextBytes;
        return 4 * ((rawBytes + 2) / 3);
    }

    public static boolean plaintextFitsSingleSms(int plaintextBytes) {
        return plaintextBytes >= 0
                && FIXED_OVERHEAD_BYTES + plaintextBytes <= MAX_RAW_PACKET_BYTES
                && encodedLengthForPlaintextBytes(plaintextBytes) <= MAX_SMS_TEXT_CHARS;
    }

    public static boolean textFitsSingleSms(String text) {
        return text != null && plaintextFitsSingleSms(utf8Bytes(text));
    }

    public static int maximumPlaintextBytes() {
        return MAX_RAW_PACKET_BYTES - FIXED_OVERHEAD_BYTES; // 87 bytes in v1
    }

    private static byte[] deriveDirectionalKey(byte[] secret, String sender, String recipient)
            throws GeneralSecurityException {
        String label = "CipherSMS/v1/AES-256-GCM\u0000from=" + sender + "\u0000to=" + recipient;
        return HkdfSha256.derive(secret, HKDF_SALT, label.getBytes(StandardCharsets.UTF_8), 32);
    }

    private static byte[] makeAad(byte[] header, String sender, String recipient) {
        byte[] context = ("CipherSMS/v1\u0000from=" + sender + "\u0000to=" + recipient)
                .getBytes(StandardCharsets.UTF_8);
        byte[] aad = new byte[header.length + context.length];
        System.arraycopy(header, 0, aad, 0, header.length);
        System.arraycopy(context, 0, aad, header.length, context.length);
        Arrays.fill(context, (byte) 0);
        return aad;
    }

    private static void validateSecret(byte[] secret) {
        if (secret == null || secret.length != 32) throw new IllegalArgumentException("Shared secret must be 32 bytes");
    }

    private static void validateNumber(String number) {
        if (number == null || !number.matches("\\+[1-9][0-9]{5,14}")) {
            throw new IllegalArgumentException("Phone number must be canonical E.164");
        }
    }

    public static final class Decoded {
        public final long counter;
        public final int type;
        public final byte[] plaintext;
        private Decoded(long counter, int type, byte[] plaintext) {
            this.counter = counter;
            this.type = type;
            this.plaintext = plaintext;
        }
    }
}
