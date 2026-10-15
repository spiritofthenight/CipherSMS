package org.ciphersms.app.crypto;

public final class Hex {
    private static final char[] DIGITS = "0123456789abcdef".toCharArray();
    private Hex() { }

    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            out[i * 2] = DIGITS[value >>> 4];
            out[i * 2 + 1] = DIGITS[value & 0x0f];
        }
        return new String(out);
    }

    public static byte[] decode(String value) {
        if (value == null || (value.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex data must have an even length");
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < value.length(); i += 2) {
            int high = Character.digit(value.charAt(i), 16);
            int low = Character.digit(value.charAt(i + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("Invalid hexadecimal data");
            out[i / 2] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
