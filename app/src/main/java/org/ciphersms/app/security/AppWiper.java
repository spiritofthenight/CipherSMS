package org.ciphersms.app.security;

import android.content.Context;

import org.ciphersms.app.data.PendingSmsStore;

import java.io.File;

/** Best-effort deletion of data inside this application's private storage areas. */
public final class AppWiper {
    private AppWiper() { }

    public static void eraseAppOwnedData(Context context) {
        Context app = context.getApplicationContext();
        // The queued-packet encryption key is app-owned cryptographic material too.
        PendingSmsStore.destroyEncryptionKey(app);
        deleteContents(app.getDataDir());
        File[] externalFiles = app.getExternalFilesDirs(null);
        if (externalFiles != null) {
            for (File dir : externalFiles) if (dir != null) deleteContents(dir);
        }
        File[] externalCaches = app.getExternalCacheDirs();
        if (externalCaches != null) {
            for (File dir : externalCaches) if (dir != null) deleteContents(dir);
        }
    }

    private static void deleteContents(File directory) {
        if (directory == null || !directory.exists()) return;
        File[] children = directory.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) deleteContents(child);
            // File deletion is best effort. Crypto-erasure occurs by destroying the vault password/key.
            try { child.delete(); } catch (SecurityException ignored) { }
        }
    }
}
