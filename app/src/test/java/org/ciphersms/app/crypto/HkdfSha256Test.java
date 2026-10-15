package org.ciphersms.app.crypto;

import org.junit.Test;
import java.util.Arrays;
import static org.junit.Assert.assertEquals;

public class HkdfSha256Test {
    @Test public void matchesRfc5869Sha256TestCaseOne() throws Exception {
        byte[] ikm = new byte[22]; Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        byte[] out = HkdfSha256.derive(ikm, salt, info, 42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                Hex.encode(out));
    }
}
