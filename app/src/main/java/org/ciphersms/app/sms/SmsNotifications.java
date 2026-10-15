package org.ciphersms.app.sms;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import org.ciphersms.app.MainActivity;

public final class SmsNotifications {
    public static final String CHANNEL_ID = "encrypted_sms_arrivals";
    private SmsNotifications() { }

    public static void createChannel(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager != null) {
                NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "Encrypted message arrivals",
                        NotificationManager.IMPORTANCE_DEFAULT);
                channel.setDescription("Notifications never include message contents.");
                channel.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
                manager.createNotificationChannel(channel);
            }
        }
    }

    public static void notifyEncryptedMessage(Context context) {
        try {
            createChannel(context);
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager == null) return;
            Intent open = new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            PendingIntent content = PendingIntent.getActivity(context, 7101, open,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? new Notification.Builder(context, CHANNEL_ID)
                    : new Notification.Builder(context);
            Notification notification = builder
                    .setSmallIcon(android.R.drawable.sym_action_chat)
                    .setContentTitle("Encrypted SMS received")
                    .setContentText("Unlock Cipher SMS to verify and read it.")
                    .setContentIntent(content)
                    .setAutoCancel(true)
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .build();
            manager.notify(7102, notification);
        } catch (SecurityException ignored) {
            // The user may deny notification permission; receiving and queuing remain independent.
        }
    }
}
