package org.ciphersms.app.data;

import android.content.Context;
import android.util.AtomicFile;

import org.ciphersms.app.crypto.Argon2idKdf;
import org.ciphersms.app.crypto.HkdfSha256;

import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** Password-encrypted vault. Plaintext JSON is held only while the vault is unlocked. */
public final class VaultStore {
    private static final byte[] VAULT_MAGIC = new byte[]{'C', 'S', 'M', '1'};
    private static final byte[] SECURITY_MAGIC = new byte[]{'C', 'S', 'V', '1'};
    private static final byte[] EMERGENCY_LABEL = "CipherSMS emergency password verifier v1".getBytes(StandardCharsets.US_ASCII);
    private static final int NONCE_BYTES = 12;
    private static final int MAX_VAULT_BYTES = 5 * 1024 * 1024;
    private static final SecureRandom RNG = new SecureRandom();

    private final Context app;
    private final File vaultPath;
    private final File securityPath;
    private byte[] salt;
    private byte[] vaultKey;
    private JSONObject data;

    public enum UnlockStatus { UNLOCKED, EMERGENCY_PASSWORD, BAD_PASSWORD, LOCKED, CORRUPT }

    public static final class UnlockResult {
        public final UnlockStatus status;
        private UnlockResult(UnlockStatus status) { this.status = status; }
    }

    public VaultStore(Context context) {
        app = context.getApplicationContext();
        vaultPath = new File(app.getFilesDir(), "vault.bin");
        securityPath = new File(app.getFilesDir(), "emergency.verifier");
    }

    public synchronized boolean isSetup() {
        return vaultPath.isFile() && securityPath.isFile();
    }

    /** True if a partial or complete installation exists; prevents silently replacing damaged state. */
    public synchronized boolean hasAnySetupFiles() {
        return vaultPath.exists() || securityPath.exists();
    }

    public synchronized boolean isUnlocked() { return vaultKey != null && data != null; }

    public synchronized void create(char[] normalPassword, char[] emergencyPassword, JSONObject initialData)
            throws IOException, GeneralSecurityException, JSONException {
        if (normalPassword == null || emergencyPassword == null || initialData == null) {
            throw new IllegalArgumentException("Missing setup data");
        }
        byte[] newSalt = new byte[Argon2idKdf.SALT_BYTES];
        RNG.nextBytes(newSalt);
        byte[] normalKey = Argon2idKdf.derive(normalPassword, newSalt);
        byte[] emergencyKey = null;
        byte[] verifier = null;
        try {
            emergencyKey = Argon2idKdf.derive(emergencyPassword, newSalt);
            verifier = HkdfSha256.hmac(emergencyKey, EMERGENCY_LABEL);
            salt = newSalt.clone();
            vaultKey = normalKey.clone();
            data = deepCopy(initialData);
            writeSecurityFile(newSalt, verifier);
            writeEncryptedVault(data);
        } catch (GeneralSecurityException | IOException | JSONException | RuntimeException ex) {
            lock();
            deleteQuietly(vaultPath);
            deleteQuietly(securityPath);
            throw ex;
        } finally {
            Arrays.fill(normalKey, (byte) 0);
            if (emergencyKey != null) Arrays.fill(emergencyKey, (byte) 0);
            if (verifier != null) Arrays.fill(verifier, (byte) 0);
            Arrays.fill(newSalt, (byte) 0);
        }
    }

    /**
     * Computes Argon2id once, checks the emergency verifier before normal unlock, then decrypts the vault.
     * When allowNormalUnlock is false, the emergency password still works but normal unlock stays throttled.
     */
    public synchronized UnlockResult unlock(char[] candidatePassword, boolean allowNormalUnlock) {
        byte[] derived = null;
        byte[] expectedVerifier = null;
        byte[] actualVerifier = null;
        try {
            SecurityRecord security = readSecurityFile();
            derived = Argon2idKdf.derive(candidatePassword, security.salt);
            actualVerifier = HkdfSha256.hmac(derived, EMERGENCY_LABEL);
            expectedVerifier = security.verifier;
            if (MessageDigest.isEqual(expectedVerifier, actualVerifier)) {
                return new UnlockResult(UnlockStatus.EMERGENCY_PASSWORD);
            }
            if (!allowNormalUnlock) return new UnlockResult(UnlockStatus.LOCKED);

            byte[] envelope = readLimited(vaultPath, MAX_VAULT_BYTES);
            if (envelope.length < 4 + Argon2idKdf.SALT_BYTES + NONCE_BYTES + 16
                    || !startsWith(envelope, VAULT_MAGIC)) {
                return new UnlockResult(UnlockStatus.CORRUPT);
            }
            byte[] envelopeSalt = Arrays.copyOfRange(envelope, 4, 4 + Argon2idKdf.SALT_BYTES);
            if (!MessageDigest.isEqual(envelopeSalt, security.salt)) {
                Arrays.fill(envelopeSalt, (byte) 0);
                return new UnlockResult(UnlockStatus.CORRUPT);
            }
            byte[] nonce = Arrays.copyOfRange(envelope, 4 + Argon2idKdf.SALT_BYTES,
                    4 + Argon2idKdf.SALT_BYTES + NONCE_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(envelope, 4 + Argon2idKdf.SALT_BYTES + NONCE_BYTES, envelope.length);
            byte[] clear = null;
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derived, "AES"), new GCMParameterSpec(128, nonce));
                cipher.updateAAD(concat(VAULT_MAGIC, envelopeSalt));
                clear = cipher.doFinal(ciphertext);
                JSONObject opened = new JSONObject(new String(clear, StandardCharsets.UTF_8));
                if (opened.optInt("schema", -1) != 1 || opened.optString("localNumber", "").isEmpty()) {
                    return new UnlockResult(UnlockStatus.CORRUPT);
                }
                lock();
                salt = envelopeSalt.clone();
                vaultKey = derived.clone();
                data = opened;
                return new UnlockResult(UnlockStatus.UNLOCKED);
            } catch (AEADBadTagException badPasswordOrCorruption) {
                return new UnlockResult(UnlockStatus.BAD_PASSWORD);
            } catch (JSONException | GeneralSecurityException | RuntimeException corrupt) {
                return new UnlockResult(UnlockStatus.CORRUPT);
            } finally {
                Arrays.fill(envelopeSalt, (byte) 0);
                Arrays.fill(nonce, (byte) 0);
                Arrays.fill(ciphertext, (byte) 0);
                if (clear != null) Arrays.fill(clear, (byte) 0);
                Arrays.fill(envelope, (byte) 0);
            }
        } catch (IOException | GeneralSecurityException | RuntimeException error) {
            return new UnlockResult(UnlockStatus.CORRUPT);
        } finally {
            if (derived != null) Arrays.fill(derived, (byte) 0);
            if (actualVerifier != null) Arrays.fill(actualVerifier, (byte) 0);
            if (expectedVerifier != null) Arrays.fill(expectedVerifier, (byte) 0);
        }
    }

    public synchronized JSONObject copyData() throws JSONException {
        if (!isUnlocked()) throw new IllegalStateException("Vault is locked");
        return deepCopy(data);
    }

    public synchronized void saveData(JSONObject updated) throws IOException, GeneralSecurityException, JSONException {
        if (!isUnlocked()) throw new IllegalStateException("Vault is locked");
        JSONObject safeCopy = deepCopy(updated);
        writeEncryptedVault(safeCopy);
        data = safeCopy;
    }

    public synchronized String localNumber() {
        if (!isUnlocked()) throw new IllegalStateException("Vault is locked");
        return data.optString("localNumber", "");
    }

    public synchronized void lock() {
        if (vaultKey != null) Arrays.fill(vaultKey, (byte) 0);
        if (salt != null) Arrays.fill(salt, (byte) 0);
        vaultKey = null;
        salt = null;
        data = null;
    }

    public synchronized void destroyFilesForReset() {
        lock();
        deleteQuietly(vaultPath);
        deleteQuietly(new File(vaultPath.getPath() + ".bak"));
        deleteQuietly(securityPath);
        deleteQuietly(new File(securityPath.getPath() + ".bak"));
    }

    private void writeEncryptedVault(JSONObject json) throws IOException, GeneralSecurityException {
        if (vaultKey == null || salt == null) throw new IllegalStateException("Vault is locked");
        byte[] clear = json.toString().getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[NONCE_BYTES];
        RNG.nextBytes(nonce);
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(vaultKey, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(concat(VAULT_MAGIC, salt));
            encrypted = cipher.doFinal(clear);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(VAULT_MAGIC);
            output.write(salt);
            output.write(nonce);
            output.write(encrypted);
            writeAtomic(vaultPath, output.toByteArray());
        } finally {
            Arrays.fill(clear, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
        }
    }

    private void writeSecurityFile(byte[] fileSalt, byte[] verifier) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(SECURITY_MAGIC);
        output.write(fileSalt);
        output.write(verifier);
        writeAtomic(securityPath, output.toByteArray());
    }

    private SecurityRecord readSecurityFile() throws IOException {
        byte[] bytes = readLimited(securityPath, 128);
        try {
            if (bytes.length != 4 + Argon2idKdf.SALT_BYTES + 32 || !startsWith(bytes, SECURITY_MAGIC)) {
                throw new IOException("Emergency verifier file is invalid");
            }
            return new SecurityRecord(
                    Arrays.copyOfRange(bytes, 4, 4 + Argon2idKdf.SALT_BYTES),
                    Arrays.copyOfRange(bytes, 4 + Argon2idKdf.SALT_BYTES, bytes.length));
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static void writeAtomic(File destination, byte[] bytes) throws IOException {
        AtomicFile atomic = new AtomicFile(destination);
        FileOutputStream stream = null;
        try {
            stream = atomic.startWrite();
            stream.write(bytes);
            stream.getFD().sync();
            atomic.finishWrite(stream);
            stream = null;
        } catch (IOException error) {
            if (stream != null) atomic.failWrite(stream);
            throw error;
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static byte[] readLimited(File file, int maximum) throws IOException {
        // openRead() performs AtomicFile's recovery of a previous complete backup after a crash.
        AtomicFile atomic = new AtomicFile(file);
        try (FileInputStream input = atomic.openRead()) {
            long length = input.getChannel().size();
            if (length < 0 || length > maximum) throw new IOException("File size is invalid");
            ByteArrayOutputStream output = new ByteArrayOutputStream((int) length);
            byte[] buffer = new byte[4096];
            int count;
            try {
                while ((count = input.read(buffer)) != -1) {
                    if (output.size() + count > maximum) throw new IOException("File exceeds size limit");
                    output.write(buffer, 0, count);
                }
                return output.toByteArray();
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
        }
    }

    private static JSONObject deepCopy(JSONObject source) throws JSONException {
        return new JSONObject(source.toString());
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        if (value.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (value[i] != prefix[i]) return false;
        return true;
    }

    private static void deleteQuietly(File file) {
        try { if (file.exists()) file.delete(); } catch (RuntimeException ignored) { }
    }

    private static final class SecurityRecord {
        final byte[] salt;
        final byte[] verifier;
        SecurityRecord(byte[] salt, byte[] verifier) { this.salt = salt; this.verifier = verifier; }
    }
}
