package org.ciphersms.app.data;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.ciphersms.app.crypto.MessagePacket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Bounded incoming queue. Candidate bodies are encrypted again at rest with an Android Keystore key
 * because a hostile sender can fabricate a Base64-looking packet before its GCM tag has been verified.
 * Sender and receive-time metadata are visible but authenticated as AAD.
 */
public final class PendingSmsStore extends SQLiteOpenHelper {
    private static final String DB_NAME = "pending_packets.db";
    private static final int DB_VERSION = 1;
    private static final int MAX_PENDING = 500;
    private static final int NONCE_BYTES = 12;
    private static final String KEY_ALIAS = "org.ciphersms.app.pending-packets.v1";

    public static final class PendingPacket {
        public final long id;
        public final String senderAddress;
        public final String encodedPacket;
        public final long receivedAt;
        public PendingPacket(long id, String senderAddress, String encodedPacket, long receivedAt) {
            this.id = id;
            this.senderAddress = senderAddress;
            this.encodedPacket = encodedPacket;
            this.receivedAt = receivedAt;
        }
    }

    public PendingSmsStore(Context context) { super(context.getApplicationContext(), DB_NAME, null, DB_VERSION); }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE pending (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "sender TEXT NOT NULL," +
                "packet_nonce BLOB NOT NULL," +
                "packet_ciphertext BLOB NOT NULL," +
                "packet_hash BLOB NOT NULL," +
                "received_at INTEGER NOT NULL," +
                "UNIQUE(sender, packet_hash))");
        db.execSQL("CREATE INDEX pending_time ON pending(received_at)");
    }

    @Override public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // No production release has shipped with an earlier schema. Fail closed instead of silently
        // migrating unauthenticated queue bodies; define a tested migration before the first release.
        throw new IllegalStateException("Unsupported pending-message database upgrade");
    }

    /** Returns true only when a new candidate was queued. */
    public synchronized boolean enqueue(String sender, String body, long receivedAt) {
        if (sender == null || sender.trim().isEmpty() || sender.trim().length() > 64
                || !MessagePacket.isTransportCandidate(body)) return false;
        String canonicalSender = sender.trim();
        byte[] packetBytes = body.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = null;
        byte[] encrypted = null;
        byte[] hash = null;
        byte[] aad = makeAad(canonicalSender, receivedAt);
        try {
            SecretKey key = getQueueKey(true);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            nonce = cipher.getIV();
            if (nonce == null || nonce.length != NONCE_BYTES) return false;
            cipher.updateAAD(aad);
            encrypted = cipher.doFinal(packetBytes);
            hash = packetHash(canonicalSender, packetBytes);

            SQLiteDatabase db = getWritableDatabase();
            ContentValues values = new ContentValues();
            values.put("sender", canonicalSender);
            values.put("packet_nonce", nonce);
            values.put("packet_ciphertext", encrypted);
            values.put("packet_hash", hash);
            values.put("received_at", receivedAt);
            long id = db.insertWithOnConflict("pending", null, values, SQLiteDatabase.CONFLICT_IGNORE);
            db.execSQL("DELETE FROM pending WHERE id NOT IN (SELECT id FROM pending ORDER BY received_at DESC, id DESC LIMIT " + MAX_PENDING + ")");
            return id != -1;
        } catch (Exception unavailable) {
            // Fail closed: don't fall back to storing the candidate packet body in cleartext.
            return false;
        } finally {
            Arrays.fill(packetBytes, (byte) 0);
            Arrays.fill(aad, (byte) 0);
            if (nonce != null) Arrays.fill(nonce, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
            if (hash != null) Arrays.fill(hash, (byte) 0);
        }
    }

    public synchronized List<PendingPacket> readAll() {
        ArrayList<PendingPacket> result = new ArrayList<>();
        ArrayList<Long> invalidRows = new ArrayList<>();
        SecretKey key;
        try {
            key = getQueueKey(false);
        } catch (Exception unavailable) {
            clearPendingRows();
            return result;
        }
        if (key == null) {
            // The local wrapping key is missing: queued packets cannot be authenticated/decrypted.
            // Delete orphaned ciphertext instead of replacing the key and misinterpreting old rows.
            clearPendingRows();
            return result;
        }

        SQLiteDatabase db = getReadableDatabase();
        try (Cursor cursor = db.query("pending",
                new String[]{"id", "sender", "packet_nonce", "packet_ciphertext", "received_at"},
                null, null, null, null, "received_at ASC, id ASC", Integer.toString(MAX_PENDING))) {
            while (cursor.moveToNext()) {
                long id = cursor.getLong(0);
                String sender = cursor.getString(1);
                if (sender == null || sender.isEmpty() || sender.length() > 64) {
                    invalidRows.add(id);
                    continue;
                }
                byte[] nonce = cursor.getBlob(2);
                byte[] encrypted = cursor.getBlob(3);
                long receivedAt = cursor.getLong(4);
                byte[] aad = makeAad(sender, receivedAt);
                byte[] clear = null;
                try {
                    if (nonce == null || nonce.length != NONCE_BYTES || encrypted == null || encrypted.length < 16) {
                        throw new IllegalArgumentException("Invalid encrypted queue row");
                    }
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                    cipher.updateAAD(aad);
                    clear = cipher.doFinal(encrypted);
                    String packet = new String(clear, StandardCharsets.UTF_8);
                    if (!MessagePacket.isTransportCandidate(packet)) {
                        invalidRows.add(id);
                    } else {
                        result.add(new PendingPacket(id, sender, packet, receivedAt));
                    }
                } catch (Exception invalidOrUnauthenticatedRow) {
                    invalidRows.add(id);
                } finally {
                    if (nonce != null) Arrays.fill(nonce, (byte) 0);
                    if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
                    Arrays.fill(aad, (byte) 0);
                    if (clear != null) Arrays.fill(clear, (byte) 0);
                }
            }
        } catch (RuntimeException databaseUnavailable) {
            return new ArrayList<>();
        }
        if (!invalidRows.isEmpty()) {
            SQLiteDatabase writable = getWritableDatabase();
            writable.beginTransaction();
            try {
                for (Long id : invalidRows) writable.delete("pending", "id = ?", new String[]{Long.toString(id)});
                writable.setTransactionSuccessful();
            } finally {
                writable.endTransaction();
            }
        }
        return result;
    }

    public synchronized void delete(long id) {
        getWritableDatabase().delete("pending", "id = ?", new String[]{Long.toString(id)});
    }

    public synchronized int size() {
        try (Cursor cursor = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM pending", null)) {
            return cursor.moveToFirst() ? cursor.getInt(0) : 0;
        }
    }

    /** Remove the app-specific key during emergency reset, alongside deleting database files. */
    public static void destroyEncryptionKey(Context context) {
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS);
        } catch (Exception ignored) {
            // Deleting app-owned files still proceeds; platform keystore deletion is best effort.
        }
    }

    private static SecretKey getQueueKey(boolean createIfMissing) throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        Key existing = store.getKey(KEY_ALIAS, null);
        if (existing instanceof SecretKey) return (SecretKey) existing;
        if (!createIfMissing) return null;
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build();
        generator.init(spec);
        return generator.generateKey();
    }

    private static byte[] makeAad(String sender, long receivedAt) {
        byte[] senderBytes = sender.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(senderBytes.length + 1 + 8);
        buffer.put(senderBytes).put((byte) 0).putLong(receivedAt);
        Arrays.fill(senderBytes, (byte) 0);
        return buffer.array();
    }

    private static byte[] packetHash(String sender, byte[] packetBytes) throws Exception {
        byte[] aad = makeAad(sender, 0L);
        byte[] input = new byte[aad.length + packetBytes.length];
        System.arraycopy(aad, 0, input, 0, aad.length);
        System.arraycopy(packetBytes, 0, input, aad.length, packetBytes.length);
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } finally {
            Arrays.fill(aad, (byte) 0);
            Arrays.fill(input, (byte) 0);
        }
    }

    private void clearPendingRows() {
        try { getWritableDatabase().delete("pending", null, null); }
        catch (RuntimeException ignored) { }
    }
}
