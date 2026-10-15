package org.ciphersms.app.security;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;

/** Persistent failed-unlock throttling. Elapsed realtime is used instead of wall-clock time. */
public final class SecurityPrefs {
    private static final String PREFS = "unlock_throttle";
    private static final String FAILURES = "failures";
    private static final String UNTIL = "until_elapsed";
    private static final String BOOT = "boot_count";
    private static final String DURATION = "lock_duration";
    private final Context app;

    public SecurityPrefs(Context context) { this.app = context.getApplicationContext(); }

    public synchronized int failures() {
        return prefs().getInt(FAILURES, 0);
    }

    /** Returns remaining milliseconds. On a reboot, an active lockout restarts for its full duration. */
    public synchronized long remainingLockMillis() {
        SharedPreferences p = prefs();
        long until = p.getLong(UNTIL, 0L);
        long duration = p.getLong(DURATION, 0L);
        if (until <= 0L || duration <= 0L) return 0L;
        int currentBoot = bootCount();
        int savedBoot = p.getInt(BOOT, -1);
        if (savedBoot != currentBoot) {
            until = SystemClock.elapsedRealtime() + duration;
            p.edit().putLong(UNTIL, until).putInt(BOOT, currentBoot).commit();
        }
        long remaining = until - SystemClock.elapsedRealtime();
        if (remaining <= 0L) {
            p.edit().putLong(UNTIL, 0L).putLong(DURATION, 0L).commit();
            return 0L;
        }
        return remaining;
    }

    public synchronized FailureResult recordFailure() {
        SharedPreferences p = prefs();
        int count = p.getInt(FAILURES, 0) + 1;
        long duration = durationForFailureCount(count);
        SharedPreferences.Editor editor = p.edit().putInt(FAILURES, count);
        if (duration > 0L) {
            editor.putLong(DURATION, duration)
                    .putLong(UNTIL, SystemClock.elapsedRealtime() + duration)
                    .putInt(BOOT, bootCount());
        }
        editor.commit();
        return new FailureResult(count, duration);
    }

    public synchronized void recordSuccess() {
        prefs().edit().putInt(FAILURES, 0).putLong(UNTIL, 0L).putLong(DURATION, 0L)
                .putInt(BOOT, bootCount()).commit();
    }

    public static long durationForFailureCount(int count) {
        if (count == 5) return 60_000L;
        if (count == 10) return 120_000L;
        if (count == 15) return 300_000L;
        if (count >= 20) return 3_600_000L;
        return 0L;
    }

    private SharedPreferences prefs() {
        return app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private int bootCount() {
        try {
            return Settings.Global.getInt(app.getContentResolver(), Settings.Global.BOOT_COUNT, -1);
        } catch (RuntimeException ignored) {
            return -1;
        }
    }

    public static String prettyTime(long millis) {
        long seconds = Math.max(1L, (millis + 999L) / 1000L);
        if (seconds >= 3600) return (seconds / 3600) + " hour(s)";
        if (seconds >= 60) return (seconds / 60) + " minute(s)";
        return seconds + " second(s)";
    }

    public static final class FailureResult {
        public final int count;
        public final long delayMillis;
        private FailureResult(int count, long delayMillis) {
            this.count = count;
            this.delayMillis = delayMillis;
        }
    }
}
