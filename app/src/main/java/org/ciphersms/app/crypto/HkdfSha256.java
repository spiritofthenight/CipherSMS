package org.ciphersms.app.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Small RFC 5869 HKDF-SHA-256 implementation with output limits enforced. */
public final class HkdfSha256 {
    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private HkdfSha256() { }

    public static byte[] derive(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length)
            throws GeneralSecurityException {
        if (inputKeyMaterial == null || inputKeyMaterial.length == 0) {
            throw new IllegalArgumentException("Input key material must not be empty");
        }
        if (length < 1 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("Invalid HKDF output length");
        }
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        byte[] prk = hmac(effectiveSalt, inputKeyMaterial);
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        int block = 1;
        try {
            while (offset < length) {
                int infoLength = info == null ? 0 : info.length;
                byte[] input = new byte[previous.length + infoLength + 1];
                System.arraycopy(previous, 0, input, 0, previous.length);
                if (infoLength > 0) System.arraycopy(info, 0, input, previous.length, infoLength);
                input[input.length - 1] = (byte) block;
                byte[] next;
                try {
                    next = hmac(prk, input);
                } finally {
                    Arrays.fill(input, (byte) 0);
                }
                Arrays.fill(previous, (byte) 0);
                previous = next;
                int count = Math.min(next.length, length - offset);
                System.arraycopy(next, 0, output, offset, count);
                offset += count;
                block++;
            }
            return output;
        } catch (GeneralSecurityException | RuntimeException ex) {
            Arrays.fill(output, (byte) 0);
            throw ex;
        } finally {
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(previous, (byte) 0);
        }
    }

    public static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        return mac.doFinal(data);
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
