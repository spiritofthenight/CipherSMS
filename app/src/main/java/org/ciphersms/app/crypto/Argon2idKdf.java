package org.ciphersms.app.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.util.Arrays;

/** Password KDF. Parameters are fixed by this protocol version, never read from a packet. */
public final class Argon2idKdf {
    // 32 MiB, 3 passes, one lane. Benchmark on supported low-end devices before release.
    public static final int MEMORY_KIB = 32 * 1024;
    public static final int ITERATIONS = 3;
    public static final int PARALLELISM = 1;
    public static final int OUTPUT_BYTES = 32;
    public static final int SALT_BYTES = 16;

    private Argon2idKdf() { }

    public static byte[] derive(char[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
        if (salt == null || salt.length != SALT_BYTES) {
            throw new IllegalArgumentException("Expected a 16-byte salt");
        }

        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KIB)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build();
        byte[] output = new byte[OUTPUT_BYTES];
        try {
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);
            generator.generateBytes(password, output);
            return output;
        } catch (RuntimeException error) {
            Arrays.fill(output, (byte) 0);
            throw error;
        } finally {
            parameters.clear();
        }
    }
}
