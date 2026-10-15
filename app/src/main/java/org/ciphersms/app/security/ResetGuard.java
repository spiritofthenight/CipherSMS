package org.ciphersms.app.security;

/** In-process guard used to avoid recreating queues during an active emergency reset. */
public final class ResetGuard {
    public static volatile boolean resetting = false;
    private ResetGuard() { }
}
