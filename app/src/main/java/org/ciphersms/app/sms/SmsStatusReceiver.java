package org.ciphersms.app.sms;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import org.ciphersms.app.security.ResetGuard;

/** Stores non-secret transport status only; it never handles keys or plaintext message bodies. */
public final class SmsStatusReceiver extends BroadcastReceiver {
    public static final String ACTION_SENT = "org.ciphersms.app.SMS_SENT";
    public static final String ACTION_DELIVERED = "org.ciphersms.app.SMS_DELIVERED";
    public static final String EXTRA_MESSAGE_ID = "message_id";
    private static final String PREFS = "sms_transport_status";

    @Override public void onReceive(Context context, Intent intent) {
        if (ResetGuard.resetting || intent == null) return;
        String id = intent.getStringExtra(EXTRA_MESSAGE_ID);
        if (id == null || id.length() > 64) return;
        String status;
        if (ACTION_SENT.equals(intent.getAction())) {
            status = getResultCode() == Activity.RESULT_OK ? "submitted_to_carrier" : "send_failed";
        } else if (ACTION_DELIVERED.equals(intent.getAction())) {
            status = getResultCode() == Activity.RESULT_OK ? "carrier_reports_delivered" : "delivery_unconfirmed";
        } else {
            return;
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(id, status + "|" + System.currentTimeMillis()).apply();
    }
}
