package org.ciphersms.app.data;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class ReplayWindowTest {
    @Test public void acceptsOutOfOrderMessagesWithinWindowButNotDuplicates() {
        ReplayWindow.Decision first = ReplayWindow.evaluate(-1, 0, 10);
        assertEquals(ReplayWindow.Status.ACCEPT, first.status);
        ReplayWindow.Decision newer = ReplayWindow.evaluate(first.highestSeen, first.bitmap, 12);
        assertEquals(ReplayWindow.Status.ACCEPT, newer.status);
        ReplayWindow.Decision delayed = ReplayWindow.evaluate(newer.highestSeen, newer.bitmap, 11);
        assertEquals(ReplayWindow.Status.ACCEPT, delayed.status);
        ReplayWindow.Decision duplicate = ReplayWindow.evaluate(delayed.highestSeen, delayed.bitmap, 11);
        assertEquals(ReplayWindow.Status.DUPLICATE, duplicate.status);
    }

    @Test public void messagesOutsideWindowAreRejectedAsTooOld() {
        ReplayWindow.Decision newest = ReplayWindow.evaluate(-1, 0, 100);
        ReplayWindow.Decision old = ReplayWindow.evaluate(newest.highestSeen, newest.bitmap, 36);
        assertEquals(ReplayWindow.Status.TOO_OLD, old.status);
    }

    @Test public void counterNeverWraps() {
        assertEquals(ReplayWindow.Status.INVALID_COUNTER, ReplayWindow.evaluate(-1, 0, 0x1_0000_0000L).status);
    }
}
