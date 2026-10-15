package org.ciphersms.app.sms;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.telephony.SmsManager;

import org.ciphersms.app.crypto.MessagePacket;

import java.util.ArrayList;

/** Plain text SMS carrier transport. The body contains only Base64 ciphertext packets. */
public final class SmsTransport {
    private SmsTransport() { }

    public static void sendOneSegment(Context context, String destinationE164, String packet, String messageId) {
        if (!MessagePacket.isTransportCandidate(packet)) {
            throw new IllegalArgumentException("The encrypted packet format is invalid");
        }
        if (packet.length() > MessagePacket.MAX_SMS_TEXT_CHARS) {
            throw new IllegalArgumentException("This packet exceeds the single-SMS limit");
        }
        SmsManager manager = context.getSystemService(SmsManager.class);
        if (manager == null) throw new IllegalStateException("This device does not provide SMS messaging");
        ArrayList<String> segments = manager.divideMessage(packet);
        if (segments == null || segments.size() != 1) {
            throw new IllegalArgumentException("Refusing to split an encrypted message into multiple SMS segments");
        }

        int code = messageId.hashCode() & 0x7fffffff;
        // PendingIntent matching ignores extras; unique data URIs prevent request-code hash collisions
        // from letting one SMS callback overwrite another message's status.
        Intent sentIntent = new Intent(context, SmsStatusReceiver.class)
                .setAction(SmsStatusReceiver.ACTION_SENT)
                .setData(Uri.parse("ciphersms://sms-status/" + messageId + "/sent"))
                .putExtra(SmsStatusReceiver.EXTRA_MESSAGE_ID, messageId);
        Intent deliveredIntent = new Intent(context, SmsStatusReceiver.class)
                .setAction(SmsStatusReceiver.ACTION_DELIVERED)
                .setData(Uri.parse("ciphersms://sms-status/" + messageId + "/delivered"))
                .putExtra(SmsStatusReceiver.EXTRA_MESSAGE_ID, messageId);
        PendingIntent sent = PendingIntent.getBroadcast(context, code, sentIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent delivered = PendingIntent.getBroadcast(context, code ^ 0x40000000, deliveredIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        manager.sendTextMessage(destinationE164, null, packet, sent, delivered);
    }
}
