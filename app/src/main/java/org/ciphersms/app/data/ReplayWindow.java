package org.ciphersms.app.data;

/**
 * 64-message replay window. Counter state is updated only after message authentication succeeds.
 * highestSeen=-1 means no authenticated messages have yet been accepted.
 */
public final class ReplayWindow {
    public enum Status { ACCEPT, DUPLICATE, TOO_OLD, INVALID_COUNTER }

    public static final int WINDOW_SIZE = 64;

    public static final class Decision {
        public final Status status;
        public final long highestSeen;
        public final long bitmap;
        private Decision(Status status, long highestSeen, long bitmap) {
            this.status = status;
            this.highestSeen = highestSeen;
            this.bitmap = bitmap;
        }
    }

    private ReplayWindow() { }

    public static Decision evaluate(long highestSeen, long bitmap, long counter) {
        if (counter < 0 || counter > 0xffff_ffffL) {
            return new Decision(Status.INVALID_COUNTER, highestSeen, bitmap);
        }
        if (highestSeen < 0) {
            return new Decision(Status.ACCEPT, counter, 1L);
        }
        if (counter > highestSeen) {
            long distance = counter - highestSeen;
            long nextBitmap = distance >= WINDOW_SIZE ? 1L : (bitmap << (int) distance) | 1L;
            return new Decision(Status.ACCEPT, counter, nextBitmap);
        }
        long distance = highestSeen - counter;
        if (distance >= WINDOW_SIZE) {
            return new Decision(Status.TOO_OLD, highestSeen, bitmap);
        }
        long bit = 1L << (int) distance;
        if ((bitmap & bit) != 0) {
            return new Decision(Status.DUPLICATE, highestSeen, bitmap);
        }
        return new Decision(Status.ACCEPT, highestSeen, bitmap | bit);
    }
}
