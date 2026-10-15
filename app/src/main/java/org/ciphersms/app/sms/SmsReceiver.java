package org.ciphersms.app.sms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;

import org.ciphersms.app.data.PendingSmsStore;
import org.ciphersms.app.security.ResetGuard;

/** Receives in the background, but never decrypts or displays message contents while the vault is locked. */
public final class SmsReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (ResetGuard.resetting || intent == null || !Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;
        SmsMessage[] messages;
        try {
            messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        } catch (RuntimeException malformed) {
            return;
        }
        // CipherSMS v1 permits exactly one SMS segment per packet. Never assemble multipart packets.
        if (messages == null || messages.length != 1 || messages[0] == null) return;
        String sender = messages[0].getOriginatingAddress();
        String body;
        try { body = messages[0].getMessageBody(); }
        catch (RuntimeException malformed) { return; }
        if (sender == null || body == null) return;
        PendingSmsStore store = null;
        try {
            store = new PendingSmsStore(context);
            boolean inserted = store.enqueue(sender, body, System.currentTimeMillis());
            if (inserted) {
                SmsNotifications.notifyEncryptedMessage(context);
                Intent queued = new Intent("org.ciphersms.app.NEW_PACKET_QUEUED").setPackage(context.getPackageName());
                context.sendBroadcast(queued);
            }
        } catch (RuntimeException ignored) {
            // Do not crash the telephony broadcast if storage is unavailable or malformed input is received.
        } finally {
            if (store != null) {
                try { store.close(); } catch (RuntimeException ignored) { }
            }
        }
    }
}
