package org.ciphersms.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.ciphersms.app.crypto.Hex;
import org.ciphersms.app.crypto.MessagePacket;
import org.ciphersms.app.crypto.PhoneNumbers;
import org.ciphersms.app.data.PendingSmsStore;
import org.ciphersms.app.data.ReplayWindow;
import org.ciphersms.app.data.VaultStore;
import org.ciphersms.app.security.AppWiper;
import org.ciphersms.app.security.ResetGuard;
import org.ciphersms.app.security.SecurityPrefs;
import org.ciphersms.app.sms.SmsNotifications;
import org.ciphersms.app.sms.SmsReceiver;
import org.ciphersms.app.sms.SmsStatusReceiver;
import org.ciphersms.app.sms.SmsTransport;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;


/** Lightweight, single-activity Java UI for the CipherSMS v1 protocol. */
public final class MainActivity extends Activity {
    private static final int PERMISSIONS_REQUEST = 410;
    private static final int COLOR_INK = Color.rgb(23, 33, 47);
    private static final int COLOR_MUTED = Color.rgb(98, 112, 132);
    private static final int COLOR_ACCENT = Color.rgb(36, 89, 169);
    private static final int COLOR_BACKGROUND = Color.rgb(243, 246, 250);
    private static final int COLOR_CARD = Color.WHITE;
    private static final int COLOR_WARNING = Color.rgb(255, 246, 223);
    private static final int COLOR_DANGER = Color.rgb(180, 35, 24);
    private static final int MAX_SAVED_MESSAGES = 500;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ACTION_NEW_PACKET = "org.ciphersms.app.NEW_PACKET_QUEUED";

    private final ExecutorService ioExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "CipherSMS-storage-crypto");
        thread.setDaemon(true);
        return thread;
    });

    private VaultStore vaultStore;
    private PendingSmsStore pendingStore;
    private LinearLayout root;
    private LinearLayout mainMessagesColumn;
    private TextView mainStatus;
    private TextView sizeMeter;
    private EditText composer;
    private Spinner contactSpinner;
    private Button sendButton;
    private Button retryButton;
    private ArrayList<JSONObject> contactChoices = new ArrayList<>();
    private String selectedContactId;
    private volatile boolean unlocked = false;
    private boolean autoLockedForBackground = false;
    private boolean permissionDialogInProgress = false;
    private boolean pendingReceiverRegistered = false;
    private boolean lengthLimitHitByFilter = false;

    private final BroadcastReceiver pendingUpdateReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (unlocked) processPendingPackets();
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        SmsNotifications.createChannel(this);
        vaultStore = new VaultStore(this);
        pendingStore = new PendingSmsStore(this);
        if (vaultStore.hasAnySetupFiles()) showUnlockScreen(vaultStore.isSetup() ? null
                : "Some vault files are missing or damaged. A valid emergency password can still erase remaining app-owned data.");
        else showSetupScreen(null);
    }

    @Override protected void onStart() {
        super.onStart();
        if (autoLockedForBackground && !unlocked && vaultStore != null && vaultStore.hasAnySetupFiles()) {
            showUnlockScreen("The vault was locked when Cipher SMS went into the background.");
        }
    }

    @Override protected void onResume() {
        super.onResume();
        registerPendingReceiverIfNeeded();
        if (unlocked) processPendingPackets();
    }


    private void registerPendingReceiverIfNeeded() {
        if (!unlocked || pendingReceiverRegistered) return;

        IntentFilter filter = new IntentFilter(ACTION_NEW_PACKET);

        androidx.core.content.ContextCompat.registerReceiver(
                this,
                pendingUpdateReceiver,
                filter,
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        );

        pendingReceiverRegistered = true;
    }


    @Override protected void onPause() {
        if (pendingReceiverRegistered) {
            try { unregisterReceiver(pendingUpdateReceiver); } catch (IllegalArgumentException ignored) { }
            pendingReceiverRegistered = false;
        }
        super.onPause();
    }

    @Override protected void onStop() {
        super.onStop();
        if (permissionDialogInProgress || ResetGuard.resetting) return;
        if (unlocked) {
            // Remove visible plaintext immediately and serialize vault locking after any active save.
            unlocked = false;
            autoLockedForBackground = true;
            clearSensitiveViews();
            ioExecutor.execute(() -> {
                if (vaultStore != null) vaultStore.lock();
            });
        } else {
            clearEditTexts(root);
        }
    }

    @Override protected void onDestroy() {
        if (pendingReceiverRegistered) {
            try { unregisterReceiver(pendingUpdateReceiver); } catch (IllegalArgumentException ignored) { }
            pendingReceiverRegistered = false;
        }
        ioExecutor.shutdown();
        super.onDestroy();
    }

    private void showSetupScreen(String message) {
        unlocked = false;
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(COLOR_BACKGROUND);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(22), dp(24), dp(22), dp(30));
        scroll.addView(page);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, -1));
        setContentView(root);

        page.addView(title("Cipher SMS", 29));
        page.addView(spacer(8));
        page.addView(body("Create a local encrypted vault. Your vault password protects contacts, shared secrets, counters, replay state, and the encrypted message archive."));
        page.addView(spacer(18));

        EditText localNumber = field("Your phone number, e.g. +31612345678", InputType.TYPE_CLASS_PHONE);
        EditText normalPassword = field("Create vault password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText normalConfirm = field("Repeat vault password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText emergencyPassword = field("Create a different emergency password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText emergencyConfirm = field("Repeat emergency password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        page.addView(sectionLabel("Your number"));
        page.addView(localNumber);
        page.addView(spacer(10));
        page.addView(sectionLabel("Vault password"));
        page.addView(normalPassword);
        page.addView(normalConfirm);
        page.addView(spacer(10));
        page.addView(sectionLabel("Emergency password"));
        page.addView(emergencyPassword);
        page.addView(emergencyConfirm);
        page.addView(spacer(10));
        page.addView(warningCard("Important: entering the emergency password in the unlock field immediately deletes Cipher SMS app-owned files, keys, contacts, and message history. This cannot erase SMS copies or data controlled by Android or other apps."));
        page.addView(spacer(12));
        TextView status = body(message == null ? "Use a strong, memorable passphrase. There is no password recovery or cloud backup." : message);
        page.addView(status);
        page.addView(spacer(12));
        Button create = button("Create encrypted vault", true);
        page.addView(create);
        create.setOnClickListener(v -> {
            String localInput = localNumber.getText().toString().trim();
            char[] pass = normalPassword.getText().toString().toCharArray();
            char[] confirm = normalConfirm.getText().toString().toCharArray();
            char[] emergency = emergencyPassword.getText().toString().toCharArray();
            char[] emergencyAgain = emergencyConfirm.getText().toString().toCharArray();
            String normalized;
            try {
                normalized = PhoneNumbers.normalizeInternational(localInput);
            } catch (Exception invalidPhone) {
                setStatus(status, "Enter a valid international phone number starting with + and country code.", true);
                clearChars(pass); clearChars(confirm); clearChars(emergency); clearChars(emergencyAgain);
                return;
            }
            if (pass.length < 10 || emergency.length < 10) {
                setStatus(status, "Use at least 10 characters for each password; longer passphrases are better.", true);
                clearChars(pass); clearChars(confirm); clearChars(emergency); clearChars(emergencyAgain);
                return;
            }
            if (!Arrays.equals(pass, confirm) || !Arrays.equals(emergency, emergencyAgain)) {
                setStatus(status, "The password confirmation does not match.", true);
                clearChars(pass); clearChars(confirm); clearChars(emergency); clearChars(emergencyAgain);
                return;
            }
            if (Arrays.equals(pass, emergency)) {
                setStatus(status, "The emergency password must be different from the vault password.", true);
                clearChars(pass); clearChars(confirm); clearChars(emergency); clearChars(emergencyAgain);
                return;
            }
            normalPassword.setText(""); normalConfirm.setText(""); emergencyPassword.setText(""); emergencyConfirm.setText("");
            localNumber.setText(normalized);
            create.setEnabled(false);
            setStatus(status, "Creating encrypted vault…", false);
            ioExecutor.execute(() -> {
                try {
                    JSONObject initial = new JSONObject();
                    initial.put("schema", 1);
                    initial.put("localNumber", normalized);
                    initial.put("contacts", new JSONArray());
                    initial.put("messages", new JSONArray());
                    initial.put("acks", new JSONArray());
                    vaultStore.create(pass, emergency, initial);
                    new SecurityPrefs(this).recordSuccess();
                    clearChars(pass); clearChars(confirm); clearChars(emergency); clearChars(emergencyAgain);
                    runOnUiThread(() -> {
                        unlocked = true;
                        autoLockedForBackground = false;
                        showMainScreen("Vault created. Add a contact and securely exchange a fresh 32-byte shared secret.");
                    });
                } catch (Exception error) {
                    clearChars(pass); clearChars(confirm); clearChars(emergency); clearChars(emergencyAgain);
                    runOnUiThread(() -> {
                        create.setEnabled(true);
                        setStatus(status, "Could not create the vault. Check available storage and try again.", true);
                    });
                }
            });
        });
    }

    private void showUnlockScreen(String message) {
        unlocked = false;
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(COLOR_BACKGROUND);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(22), dp(32), dp(22), dp(30));
        scroll.addView(page);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, -1));
        setContentView(root);

        page.addView(title("Cipher SMS", 29));
        page.addView(spacer(8));
        page.addView(body("Your message archive and contact secrets are stored in a password-encrypted vault on this device."));
        page.addView(spacer(24));
        EditText password = field("Vault password or emergency password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        page.addView(password);
        page.addView(spacer(10));
        page.addView(warningCard("Emergency password warning: entering your emergency password here immediately deletes all Cipher SMS app-owned data and returns to first-time setup."));
        page.addView(spacer(12));
        TextView status = body(message == null ? "No password recovery exists. Keep your vault and emergency passwords safe." : message);
        page.addView(status);
        page.addView(spacer(14));
        Button unlockButton = button("Unlock vault", true);
        page.addView(unlockButton);
        unlockButton.setOnClickListener(v -> {
            char[] candidate = password.getText().toString().toCharArray();
            if (candidate.length == 0) {
                setStatus(status, "Enter your vault password.", true);
                return;
            }
            password.setText("");
            unlockButton.setEnabled(false);
            setStatus(status, "Checking password…", false);
            ioExecutor.execute(() -> {
                SecurityPrefs throttle = new SecurityPrefs(this);
                long remaining = throttle.remainingLockMillis();
                VaultStore.UnlockResult result = vaultStore.unlock(candidate, remaining == 0L);
                clearChars(candidate);
                if (result.status == VaultStore.UnlockStatus.UNLOCKED) {
                    throttle.recordSuccess();
                    runOnUiThread(() -> {
                        unlocked = true;
                        autoLockedForBackground = false;
                        showMainScreen("Vault unlocked. Stored message text is decrypted only for display.");
                    });
                } else if (result.status == VaultStore.UnlockStatus.EMERGENCY_PASSWORD) {
                    ResetGuard.resetting = true;
                    vaultStore.destroyFilesForReset();
                    try { pendingStore.close(); } catch (RuntimeException ignored) { }
                    AppWiper.eraseAppOwnedData(this);
                    runOnUiThread(() -> {
                        pendingStore = new PendingSmsStore(this);
                        vaultStore = new VaultStore(this);
                        autoLockedForBackground = false;
                        ResetGuard.resetting = false;
                        Toast.makeText(this, "Cipher SMS app-owned data was erased. Set up a fresh vault.", Toast.LENGTH_LONG).show();
                        showSetupScreen("Emergency reset completed. No prior app contacts, keys, or messages remain.");
                    });
                } else if (result.status == VaultStore.UnlockStatus.LOCKED) {
                    long lockLeft = Math.max(remaining, throttle.remainingLockMillis());
                    runOnUiThread(() -> {
                        unlockButton.setEnabled(true);
                        setStatus(status, "Too many failed attempts. Try again in " + SecurityPrefs.prettyTime(lockLeft)
                                + ". The emergency password still triggers the destructive reset.", true);
                    });
                } else if (result.status == VaultStore.UnlockStatus.BAD_PASSWORD) {
                    SecurityPrefs.FailureResult failure = throttle.recordFailure();
                    long lockLeft = throttle.remainingLockMillis();
                    String text = "Incorrect password. Consecutive failures: " + failure.count + ".";
                    if (failure.delayMillis > 0L) text += " Try again in " + SecurityPrefs.prettyTime(lockLeft) + ".";
                    runOnUiThread(() -> {
                        unlockButton.setEnabled(true);
                        setStatus(status, text, true);
                    });
                } else {
                    runOnUiThread(() -> {
                        unlockButton.setEnabled(true);
                        setStatus(status, "The local vault or security metadata is damaged. Do not keep retrying; there is no automatic recovery or backup.", true);
                    });
                }
            });
        });
    }

    private void showMainScreen(String message) {
        if (!unlocked || vaultStore == null || !vaultStore.isUnlocked()) return;
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(COLOR_BACKGROUND);
        setContentView(root);

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(18), dp(12), dp(18), dp(8));
        header.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout titleBlock = new LinearLayout(this);
        titleBlock.setOrientation(LinearLayout.VERTICAL);
        titleBlock.addView(title("Cipher SMS", 23));
        titleBlock.addView(smallText("Encrypted one-SMS messages", COLOR_MUTED));
        header.addView(titleBlock, new LinearLayout.LayoutParams(0, -2, 1f));
        Button lock = button("Lock", false);
        lock.setMinWidth(dp(60));
        header.addView(lock);
        root.addView(header);
        lock.setOnClickListener(v -> lockNow());

        LinearLayout notice = new LinearLayout(this);
        notice.setOrientation(LinearLayout.VERTICAL);
        notice.setPadding(dp(14), dp(10), dp(14), dp(10));
        notice.setBackground(round(COLOR_WARNING, 12));
        TextView warning = smallText("Experimental build — not independently audited. Do not rely on it for high-risk communications yet.", Color.rgb(109, 75, 13));
        notice.addView(warning);
        LinearLayout.LayoutParams noticeParams = new LinearLayout.LayoutParams(-1, -2);
        noticeParams.setMargins(dp(14), 0, dp(14), dp(8));
        root.addView(notice, noticeParams);

        LinearLayout permissionRow = new LinearLayout(this);
        permissionRow.setOrientation(LinearLayout.HORIZONTAL);
        permissionRow.setGravity(Gravity.CENTER_VERTICAL);
        permissionRow.setPadding(dp(14), dp(2), dp(14), dp(4));
        TextView permissionLabel = smallText("", COLOR_MUTED);
        permissionRow.addView(permissionLabel, new LinearLayout.LayoutParams(0, -2, 1f));
        Button permissionButton = button("Grant SMS permissions", false);
        permissionButton.setTextSize(12);
        permissionRow.addView(permissionButton);
        root.addView(permissionRow);
        refreshPermissionRow(permissionLabel, permissionButton);
        permissionButton.setOnClickListener(v -> requestSmsPermissions());

        LinearLayout contactCard = card();
        contactCard.setPadding(dp(14), dp(10), dp(14), dp(10));
        LinearLayout contactHeader = new LinearLayout(this);
        contactHeader.setOrientation(LinearLayout.HORIZONTAL);
        contactHeader.setGravity(Gravity.CENTER_VERTICAL);
        contactHeader.addView(sectionLabel("Contact"), new LinearLayout.LayoutParams(0, -2, 1f));
        Button addContact = button("+ Add", false);
        addContact.setTextSize(12);
        contactHeader.addView(addContact);
        contactCard.addView(contactHeader);
        contactSpinner = new Spinner(this);
        contactCard.addView(contactSpinner, new LinearLayout.LayoutParams(-1, dp(48)));
        LinearLayout contactActions = new LinearLayout(this);
        contactActions.setOrientation(LinearLayout.HORIZONTAL);
        Button removeContact = button("Remove contact", false);
        removeContact.setTextSize(12);
        contactActions.addView(removeContact);
        contactCard.addView(contactActions);
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(-1, -2);
        cardParams.setMargins(dp(14), 0, dp(14), dp(8));
        root.addView(contactCard, cardParams);
        addContact.setOnClickListener(v -> showAddContactDialog());
        removeContact.setOnClickListener(v -> confirmRemoveSelectedContact());
        mainStatus = body(message == null ? "" : message);
        mainStatus.setTextSize(12);
        mainStatus.setMaxLines(3);
        mainStatus.setPadding(dp(16), dp(0), dp(16), dp(6));
        root.addView(mainStatus);

        ScrollView messagesScroll = new ScrollView(this);
        messagesScroll.setFillViewport(false);
        mainMessagesColumn = new LinearLayout(this);
        mainMessagesColumn.setOrientation(LinearLayout.VERTICAL);
        mainMessagesColumn.setPadding(dp(14), dp(4), dp(14), dp(12));
        messagesScroll.addView(mainMessagesColumn);
        root.addView(messagesScroll, new LinearLayout.LayoutParams(-1, 0, 1f));

        LinearLayout composerPanel = new LinearLayout(this);
        composerPanel.setOrientation(LinearLayout.VERTICAL);
        composerPanel.setPadding(dp(14), dp(10), dp(14), dp(12));
        composerPanel.setBackground(round(COLOR_CARD, 16));
        LinearLayout.LayoutParams composerPanelParams = new LinearLayout.LayoutParams(-1, -2);
        composerPanelParams.setMargins(dp(10), dp(4), dp(10), dp(8));
        root.addView(composerPanel, composerPanelParams);
        composer = new EditText(this);
        composer.setHint("Write a message…");
        composer.setTextColor(COLOR_INK);
        composer.setHintTextColor(COLOR_MUTED);
        composer.setGravity(Gravity.TOP | Gravity.START);
        composer.setMinLines(2);
        composer.setMaxLines(5);
        composer.setPadding(dp(12), dp(10), dp(12), dp(10));
        composer.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        composer.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        composer.setSaveEnabled(false);
        composer.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        composer.setBackground(round(COLOR_BACKGROUND, 12));
        composer.setFilters(new InputFilter[]{new SingleSmsInputFilter()});
        composerPanel.addView(composer, new LinearLayout.LayoutParams(-1, -2));
        sizeMeter = smallText("Encrypted packet: 0 / 160 SMS characters", COLOR_MUTED);
        sizeMeter.setPadding(dp(2), dp(7), dp(2), dp(5));
        composerPanel.addView(sizeMeter);
        LinearLayout sendRow = new LinearLayout(this);
        sendRow.setOrientation(LinearLayout.HORIZONTAL);
        sendRow.setGravity(Gravity.CENTER_VERTICAL);
        retryButton = button("Retry last", false);
        retryButton.setTextSize(12);
        sendRow.addView(retryButton);
        sendButton = button("Encrypt & send", true);
        LinearLayout.LayoutParams sendParams = new LinearLayout.LayoutParams(0, dp(48), 1f);
        sendParams.setMargins(dp(8), 0, 0, 0);
        sendRow.addView(sendButton, sendParams);
        composerPanel.addView(sendRow);
        composer.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                updateSizeMeter();
                if (lengthLimitHitByFilter) {
                    lengthLimitHitByFilter = false;
                    showLengthLimitReached();
                }
            }
            @Override public void afterTextChanged(Editable s) { }
        });
        sendButton.setOnClickListener(v -> sendCurrentMessage());
        retryButton.setOnClickListener(v -> confirmRetryLatest());
        contactSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(android.widget.AdapterView<?> parent, View view, int position, long id) {
                if (position >= 0 && position < contactChoices.size()) selectedContactId = contactChoices.get(position).optString("id", null);
                else selectedContactId = null;
                refreshMessages();
                updateSizeMeter();
            }
            @Override public void onNothingSelected(android.widget.AdapterView<?> parent) {
                selectedContactId = null;
                refreshMessages();
                updateSizeMeter();
            }
        });
        refreshContactPicker();
        updateSizeMeter();
        refreshMessages();
        pruneTransportStatuses();
        registerPendingReceiverIfNeeded();
        processPendingPackets();
        if (hasSendPermission()) flushPendingAcks();
    }

    private void refreshPermissionRow(TextView label, Button button) {
        boolean canSend = checkSelfPermission(Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED;
        boolean canReceive = checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED;
        boolean canNotify = Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
        if (canSend && canReceive && canNotify) {
            label.setText("SMS permissions granted");
            button.setVisibility(View.GONE);
        } else {
            label.setText("SMS is required; notifications are optional but useful for incoming packets.");
            button.setText("Grant permissions");
            button.setVisibility(View.VISIBLE);
        }
    }

    private void requestSmsPermissions() {
        ArrayList<String> wanted = new ArrayList<>();
        if (checkSelfPermission(Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) wanted.add(Manifest.permission.SEND_SMS);
        if (checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) wanted.add(Manifest.permission.RECEIVE_SMS);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            wanted.add(Manifest.permission.POST_NOTIFICATIONS);
        }
        if (wanted.isEmpty()) return;
        permissionDialogInProgress = true;
        requestPermissions(wanted.toArray(new String[0]), PERMISSIONS_REQUEST);
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSIONS_REQUEST) {
            permissionDialogInProgress = false;
            if (unlocked) showMainScreen(hasSmsPermissions()
                    ? "SMS permissions are available. Incoming packets will be verified when queued."
                    : "SMS permissions were not fully granted. Use the permission button to try again.");
        }
    }

    private boolean hasSmsPermissions() {
        return checkSelfPermission(Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED
                && checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED;
    }


    private void refreshContactPicker() {
        if (!unlocked || contactSpinner == null) return;
        ArrayList<JSONObject> list = new ArrayList<>();
        ArrayList<String> labels = new ArrayList<>();
        try {
            JSONObject data = vaultStore.copyData();
            JSONArray contacts = data.optJSONArray("contacts");
            if (contacts != null) {
                for (int i = 0; i < contacts.length(); i++) {
                    JSONObject c = contacts.optJSONObject(i);
                    if (c == null) continue;
                    list.add(c);
                    labels.add(c.optString("name", "Contact") + "  ·  " + c.optString("number", ""));
                }
            }
        } catch (Exception ignored) { }
        contactChoices = list;
        if (selectedContactId == null || findContactById(selectedContactId, list) == null) {
            selectedContactId = list.isEmpty() ? null : list.get(0).optString("id", null);
        }
        if (labels.isEmpty()) labels.add("No contacts yet — add one");
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, labels);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        contactSpinner.setAdapter(adapter);
        int selectedPosition = 0;
        for (int i = 0; i < list.size(); i++) if (selectedContactId != null && selectedContactId.equals(list.get(i).optString("id"))) selectedPosition = i;
        contactSpinner.setSelection(selectedPosition);
        if (list.isEmpty()) {
            contactSpinner.setEnabled(false);
            sendButton.setEnabled(false);
            retryButton.setEnabled(false);
        } else {
            contactSpinner.setEnabled(true);
            updateSizeMeter();
        }
    }

    private static JSONObject findContactById(String id, List<JSONObject> contacts) {
        if (id == null) return null;
        for (JSONObject contact : contacts) if (id.equals(contact.optString("id"))) return contact;
        return null;
    }

    private void updateSizeMeter() {
        if (composer == null || sizeMeter == null) return;
        String text = composer.getText().toString();
        int bytes = MessagePacket.utf8Bytes(text);
        int encodedChars = MessagePacket.encodedLengthForPlaintextBytes(bytes);
        boolean fits = MessagePacket.plaintextFitsSingleSms(bytes);
        int remaining = Math.max(0, MessagePacket.maximumPlaintextBytes() - bytes);
        if (fits) {
            sizeMeter.setText("Encrypted packet: " + encodedChars + " / 160 SMS characters  ·  " + remaining + " UTF-8 bytes available");
            sizeMeter.setTextColor(COLOR_MUTED);
        } else {
            sizeMeter.setText("SMS length limit reached. Shorten the message to type more.");
            sizeMeter.setTextColor(COLOR_DANGER);
        }
        sendButton.setEnabled(fits && !text.isEmpty() && selectedContactId != null && hasSmsPermissions());
    }

    private void showLengthLimitReached() {
        if (sizeMeter != null) {
            sizeMeter.setText("SMS length limit reached — additional text was blocked. Delete text to continue.");
            sizeMeter.setTextColor(COLOR_DANGER);
        }
    }

    private final class SingleSmsInputFilter implements InputFilter {
        @Override public CharSequence filter(CharSequence source, int start, int end, android.text.Spanned dest,
                                             int dstart, int dend) {
            String base = dest.subSequence(0, dstart).toString() + dest.subSequence(dend, dest.length());
            String insertion = source.subSequence(start, end).toString();
            String candidate = base.substring(0, dstart) + insertion + base.substring(dstart);
            if (MessagePacket.textFitsSingleSms(candidate)) return null;

            // Keep the largest prefix that fits, preserving Unicode code points (never split a surrogate pair).
            int cut = insertion.length();
            while (cut > 0) {
                cut--;
                if (cut > 0 && Character.isHighSurrogate(insertion.charAt(cut - 1))
                        && Character.isLowSurrogate(insertion.charAt(cut))) continue;
                String prefix = insertion.substring(0, cut);
                candidate = base.substring(0, dstart) + prefix + base.substring(dstart);
                if (MessagePacket.textFitsSingleSms(candidate)) {
                    lengthLimitHitByFilter = true;
                    return prefix;
                }
            }
            // If no character can be accepted, TextWatcher will not run; update the meter here.
            lengthLimitHitByFilter = false;
            showLengthLimitReached();
            return dest.subSequence(dstart, dend); // a rejected insertion must not delete selected text
        }
    }

    private void sendCurrentMessage() {
        if (!unlocked || !hasSmsPermissions()) {
            Toast.makeText(this, "Grant SMS permissions and unlock the vault first.", Toast.LENGTH_LONG).show();
            return;
        }
        if (selectedContactId == null) {
            Toast.makeText(this, "Add a contact first.", Toast.LENGTH_SHORT).show();
            return;
        }
        String plaintext = composer.getText().toString();
        if (plaintext.isEmpty()) return;
        byte[] clear = plaintext.getBytes(StandardCharsets.UTF_8);
        if (!MessagePacket.plaintextFitsSingleSms(clear.length)) {
            Toast.makeText(this, "This message exceeds the one-SMS limit. Shorten it first.", Toast.LENGTH_LONG).show();
            Arrays.fill(clear, (byte) 0);
            return;
        }
        String contactId = selectedContactId;
        sendButton.setEnabled(false);
        mainStatus.setText("Encrypting and saving message…");
        ioExecutor.execute(() -> {
            String newMessageId = UUID.randomUUID().toString();
            String packet = null;
            String destination = null;
            try {
                JSONObject data = vaultStore.copyData();
                JSONObject contact = findContactByIdInData(data, contactId);
                if (contact == null) throw new IllegalStateException("Selected contact no longer exists");
                long counter = contact.optLong("nextSendCounter", 0L);
                if (counter < 0 || counter > MessagePacket.MAX_COUNTER) {
                    throw new IllegalStateException("This contact's message counter is exhausted. Create a new shared key before sending again.");
                }
                String local = data.optString("localNumber");
                destination = contact.getString("number");
                byte[] secret = Hex.decode(contact.getString("secretHex"));
                try {
                    packet = MessagePacket.encrypt(secret, local, destination, counter, clear);
                    Arrays.fill(clear, (byte) 0);
                } finally {
                    Arrays.fill(secret, (byte) 0);
                }
                SmsManager manager = getSystemService(SmsManager.class);
                if (manager == null || manager.divideMessage(packet).size() != 1 || packet.length() > MessagePacket.MAX_SMS_TEXT_CHARS) {
                    throw new IllegalArgumentException("Android indicates this packet would exceed one SMS. It was not sent.");
                }
                contact.put("nextSendCounter", counter + 1L); // persisted before any send attempt
                JSONArray messages = data.optJSONArray("messages");
                if (messages == null) { messages = new JSONArray(); data.put("messages", messages); }
                JSONObject record = new JSONObject();
                record.put("id", newMessageId);
                record.put("contactId", contactId);
                record.put("direction", "out");
                record.put("kind", "message");
                record.put("counter", counter);
                record.put("peerAccepted", false);
                record.put("timestamp", System.currentTimeMillis());
                record.put("packet", packet); // only encrypted packet is stored; no plaintext message field
                messages.put(record);
                trimMessages(messages);
                vaultStore.saveData(data); // packet + counter committed atomically before carrier send
                setTransportStatus(newMessageId, "send_requested");
                SmsTransport.sendOneSegment(this, destination, packet, newMessageId);
                String display = "Encrypted packet saved and submitted to Android. Carrier delivery is not yet confirmed.";
                runOnUiThread(() -> {
                    Arrays.fill(clear, (byte) 0);
                    if (!unlocked) return;
                    composer.setText("");
                    setMainStatus(display, false);
                    refreshMessages();
                    updateSizeMeter();
                });
            } catch (Exception error) {
                String id = newMessageId;
                if (packet != null) setTransportStatus(id, "submission_failed");
                String safeMessage = error instanceof IllegalArgumentException || error instanceof IllegalStateException
                        ? error.getMessage() : "Could not save or submit this message. Check SMS permissions and device service.";
                runOnUiThread(() -> {
                    Arrays.fill(clear, (byte) 0);
                    if (!unlocked) return;
                    setMainStatus(safeMessage == null ? "Message could not be sent." : safeMessage, true);
                    refreshMessages();
                    updateSizeMeter();
                });
            }
        });
    }

    private void confirmRetryLatest() {
        if (selectedContactId == null || !unlocked) return;
        JSONObject latest = latestOutgoingRecord(selectedContactId);
        if (latest == null) {
            Toast.makeText(this, "No saved outgoing message to retry for this contact.", Toast.LENGTH_SHORT).show();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Resend the exact same SMS?")
                .setMessage("This resends the already-saved encrypted packet. If the first SMS arrived, the receiver should reject the duplicate. Your carrier may charge for another SMS.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Resend packet", (dialog, which) -> retryPacket(latest))
                .show();
    }

    private JSONObject latestOutgoingRecord(String contactId) {
        try {
            JSONArray messages = vaultStore.copyData().optJSONArray("messages");
            if (messages == null) return null;
            for (int i = messages.length() - 1; i >= 0; i--) {
                JSONObject record = messages.optJSONObject(i);
                if (record != null && contactId.equals(record.optString("contactId")) && "out".equals(record.optString("direction"))
                        && "message".equals(record.optString("kind", "message"))) return record;
            }
        } catch (Exception ignored) { }
        return null;
    }

    private void retryPacket(JSONObject record) {
        if (!unlocked || !hasSmsPermissions()) return;
        String packet = record.optString("packet", "");
        String id = record.optString("id", "");
        String contactId = record.optString("contactId", "");
        JSONObject contact = findContactById(contactId, contactChoices);
        if (contact == null || packet.isEmpty() || id.isEmpty()) return;
        String destination = contact.optString("number", "");
        ioExecutor.execute(() -> {
            try {
                setTransportStatus(id, "send_requested");
                SmsTransport.sendOneSegment(this, destination, packet, id); // exact same packet, nonce and counter
                runOnUiThread(() -> setMainStatus("Retry submitted. The receiver will ignore it if already accepted.", false));
            } catch (Exception error) {
                setTransportStatus(id, "submission_failed");
                runOnUiThread(() -> setMainStatus("Retry could not be submitted. The original encrypted packet remains saved.", true));
            }
        });
    }

    private void refreshMessages() {
        if (!unlocked || mainMessagesColumn == null || vaultStore == null) return;
        mainMessagesColumn.removeAllViews();
        if (selectedContactId == null) {
            mainMessagesColumn.addView(body("Add a trusted contact to begin. Generate a new shared secret for each relationship and exchange it using a separate trusted channel."));
            retryButton.setEnabled(false);
            return;
        }
        try {
            JSONObject data = vaultStore.copyData();
            JSONObject contact = findContactByIdInData(data, selectedContactId);
            if (contact == null) {
                mainMessagesColumn.addView(body("Select or add a contact."));
                retryButton.setEnabled(false);
                return;
            }
            JSONArray messages = data.optJSONArray("messages");
            ArrayList<JSONObject> records = new ArrayList<>();
            if (messages != null) {
                for (int i = 0; i < messages.length(); i++) {
                    JSONObject record = messages.optJSONObject(i);
                    if (record != null && selectedContactId.equals(record.optString("contactId"))) records.add(record);
                }
            }
            int start = Math.max(0, records.size() - 60);
            if (records.isEmpty()) mainMessagesColumn.addView(body("No accepted messages yet. Incoming SMS are verified before appearing here."));
            for (int i = start; i < records.size(); i++) {
                JSONObject record = records.get(i);
                String direction = record.optString("direction", "in");
                String local = data.optString("localNumber");
                String peer = contact.optString("number");
                String sender = "out".equals(direction) ? local : peer;
                String recipient = "out".equals(direction) ? peer : local;
                String bodyText;
                try {
                    byte[] secret = Hex.decode(contact.getString("secretHex"));
                    MessagePacket.Decoded decoded;
                    try { decoded = MessagePacket.decrypt(secret, sender, recipient, record.getString("packet")); }
                    finally { Arrays.fill(secret, (byte) 0); }
                    try {
                        bodyText = StandardCharsets.UTF_8.newDecoder()
                                .onMalformedInput(CodingErrorAction.REPORT)
                                .onUnmappableCharacter(CodingErrorAction.REPORT)
                                .decode(ByteBuffer.wrap(decoded.plaintext)).toString();
                    } catch (CharacterCodingException invalidUtf8) {
                        bodyText = "[Authenticated packet contained invalid UTF-8 and was not displayed as text]";
                    } finally {
                        Arrays.fill(decoded.plaintext, (byte) 0);
                    }
                } catch (Exception invalidStoredPacket) {
                    bodyText = "[Stored packet could not be decrypted. It was not shown as trusted text.]";
                }
                LinearLayout messageCard = new LinearLayout(this);
                messageCard.setOrientation(LinearLayout.VERTICAL);
                messageCard.setPadding(dp(12), dp(9), dp(12), dp(9));
                messageCard.setBackground(round("out".equals(direction) ? Color.rgb(229, 239, 255) : COLOR_CARD, 12));
                TextView meta = smallText(("out".equals(direction) ? "You" : contact.optString("name", "Contact"))
                        + "  ·  " + android.text.format.DateFormat.format("yyyy-MM-dd HH:mm", record.optLong("timestamp")), COLOR_MUTED);
                messageCard.addView(meta);
                TextView content = body(bodyText);
                content.setTextSize(15);
                messageCard.addView(content);
                if ("out".equals(direction)) {
                    String id = record.optString("id", "");
                    String status = transportStatus(id);
                    String deliveryText = record.optBoolean("peerAccepted", false)
                            ? "Recipient app accepted this authenticated message (not proof that a person read it)."
                            : statusText(status);
                    TextView transport = smallText(deliveryText, COLOR_MUTED);
                    transport.setPadding(0, dp(4), 0, 0);
                    messageCard.addView(transport);
                }
                LinearLayout.LayoutParams mp = new LinearLayout.LayoutParams(-1, -2);
                mp.setMargins(0, 0, 0, dp(8));
                mainMessagesColumn.addView(messageCard, mp);
            }
            retryButton.setEnabled(!records.isEmpty() && hasSmsPermissions());
        } catch (Exception error) {
            mainMessagesColumn.addView(body("Message history could not be loaded from the encrypted vault."));
            retryButton.setEnabled(false);
        }
    }

    private void processPendingPackets() {
        if (!unlocked || ResetGuard.resetting) return;
        ioExecutor.execute(() -> {
            int acceptedMessages = 0;
            int acceptedAcks = 0;
            int rejected = 0;
            boolean storageError = false;
            try {
                List<PendingSmsStore.PendingPacket> queue = pendingStore.readAll();
                for (PendingSmsStore.PendingPacket pending : queue) {
                    if (!unlocked || ResetGuard.resetting) return;
                    JSONObject data;
                    try { data = vaultStore.copyData(); }
                    catch (Exception locked) { return; }
                    String local = data.optString("localNumber", "");
                    String senderNumber = PhoneNumbers.normalizeIncoming(pending.senderAddress, local);
                    JSONObject contact = null;
                    JSONArray contacts = data.optJSONArray("contacts");
                    if (senderNumber != null && contacts != null) {
                        for (int i = 0; i < contacts.length(); i++) {
                            JSONObject candidate = contacts.optJSONObject(i);
                            if (candidate != null && senderNumber.equals(candidate.optString("number"))) {
                                contact = candidate;
                                break;
                            }
                        }
                    }
                    if (contact == null) continue; // Keep unknown senders in the bounded queue until a contact is added.

                    String contactId = contact.optString("id", "");
                    byte[] secret = null;
                    MessagePacket.Decoded decoded = null;
                    try {
                        secret = Hex.decode(contact.getString("secretHex"));
                        decoded = MessagePacket.decrypt(secret, senderNumber, local, pending.encodedPacket);
                    } catch (Exception unauthenticated) {
                        pendingStore.delete(pending.id);
                        rejected++;
                        if (secret != null) Arrays.fill(secret, (byte) 0);
                        continue;
                    }

                    try {
                        if (decoded.type == MessagePacket.TYPE_ACK && decoded.plaintext.length != 4) {
                            pendingStore.delete(pending.id);
                            rejected++;
                            continue;
                        }
                        if (decoded.type == MessagePacket.TYPE_MESSAGE && !isValidUtf8(decoded.plaintext)) {
                            pendingStore.delete(pending.id);
                            rejected++;
                            continue;
                        }

                        long highest = contact.optLong("receiveHighest", -1L);
                        long bitmap = contact.optLong("receiveBitmap", 0L);
                        ReplayWindow.Decision decision = ReplayWindow.evaluate(highest, bitmap, decoded.counter);
                        if (decision.status == ReplayWindow.Status.DUPLICATE
                                || decision.status == ReplayWindow.Status.TOO_OLD) {
                            // A duplicate or very late retry of a previously accepted text packet may mean
                            // its ACK was dropped. Re-send the previously saved ACK exactly; never encrypt
                            // a second ACK with a reused counter. An unseen packet outside the window stays rejected.
                            if (decoded.type == MessagePacket.TYPE_MESSAGE) {
                                JSONObject savedAck = findAckForCounter(data, contactId, decoded.counter);
                                pendingStore.delete(pending.id);
                                rejected++;
                                if (savedAck != null && hasSendPermission()) transmitSavedAck(savedAck, true);
                            } else {
                                pendingStore.delete(pending.id);
                                rejected++;
                            }
                            continue;
                        }
                        if (decision.status != ReplayWindow.Status.ACCEPT) {
                            pendingStore.delete(pending.id);
                            rejected++;
                            continue;
                        }

                        contact.put("receiveHighest", decision.highestSeen);
                        contact.put("receiveBitmap", decision.bitmap);
                        if (decoded.type == MessagePacket.TYPE_MESSAGE) {
                            JSONArray messages = data.optJSONArray("messages");
                            if (messages == null) { messages = new JSONArray(); data.put("messages", messages); }
                            JSONObject message = new JSONObject();
                            message.put("id", UUID.randomUUID().toString());
                            message.put("contactId", contactId);
                            message.put("direction", "in");
                            message.put("kind", "message");
                            message.put("counter", decoded.counter);
                            message.put("timestamp", pending.receivedAt);
                            message.put("packet", pending.encodedPacket); // no plaintext field is ever stored
                            messages.put(message);
                            trimMessages(messages);

                            JSONObject ackRecord = null;
                            long ackCounter = contact.optLong("nextSendCounter", 0L);
                            if (ackCounter >= 0 && ackCounter <= MessagePacket.MAX_COUNTER) {
                                byte[] ackPayload = ByteBuffer.allocate(4).putInt((int) decoded.counter).array();
                                try {
                                    String ackPacket = MessagePacket.encryptTyped(secret, local, senderNumber,
                                            MessagePacket.TYPE_ACK, ackCounter, ackPayload);
                                    contact.put("nextSendCounter", ackCounter + 1L);
                                    JSONArray acks = data.optJSONArray("acks");
                                    if (acks == null) { acks = new JSONArray(); data.put("acks", acks); }
                                    ackRecord = new JSONObject();
                                    ackRecord.put("id", UUID.randomUUID().toString());
                                    ackRecord.put("contactId", contactId);
                                    ackRecord.put("ackForCounter", decoded.counter);
                                    ackRecord.put("counter", ackCounter);
                                    ackRecord.put("packet", ackPacket);
                                    ackRecord.put("timestamp", System.currentTimeMillis());
                                    acks.put(ackRecord);
                                    trimAcks(acks);
                                } catch (GeneralSecurityException cryptoError) {
                                    // The authenticated incoming message can still be stored if ACK creation fails.
                                    // The peer will see delivery as unconfirmed rather than false success.
                                } finally {
                                    Arrays.fill(ackPayload, (byte) 0);
                                }
                            }
                            try {
                                vaultStore.saveData(data); // accepted message + replay state + ACK/counter are atomic
                            } catch (Exception persistenceFailure) {
                                storageError = true;
                                break; // retain this queue entry so processing can retry after storage recovers
                            }
                            pendingStore.delete(pending.id);
                            acceptedMessages++;
                            if (ackRecord != null && hasSendPermission()) transmitSavedAck(ackRecord, false);
                        } else {
                            long acknowledgedCounter = Integer.toUnsignedLong(ByteBuffer.wrap(decoded.plaintext).getInt());
                            boolean matchedOutgoing = false;
                            JSONArray messages = data.optJSONArray("messages");
                            if (messages != null) {
                                for (int i = 0; i < messages.length(); i++) {
                                    JSONObject outgoing = messages.optJSONObject(i);
                                    if (outgoing != null && contactId.equals(outgoing.optString("contactId"))
                                            && "out".equals(outgoing.optString("direction"))
                                            && "message".equals(outgoing.optString("kind", "message"))
                                            && outgoing.optLong("counter", -2L) == acknowledgedCounter) {
                                        outgoing.put("peerAccepted", true);
                                        outgoing.put("peerAcceptedAt", System.currentTimeMillis());
                                        matchedOutgoing = true;
                                        break;
                                    }
                                }
                            }
                            try {
                                vaultStore.saveData(data); // replay window and peer-acceptance flag are atomic
                            } catch (Exception persistenceFailure) {
                                storageError = true;
                                break;
                            }
                            pendingStore.delete(pending.id);
                            if (matchedOutgoing) acceptedAcks++;
                            else rejected++; // valid but unrelated/old ACK: consumed safely, no message shown
                        }
                    } catch (Exception protocolError) {
                        pendingStore.delete(pending.id);
                        rejected++;
                    } finally {
                        if (secret != null) Arrays.fill(secret, (byte) 0);
                        if (decoded != null) Arrays.fill(decoded.plaintext, (byte) 0);
                    }
                }
            } catch (RuntimeException unavailable) {
                storageError = true;
            }
            final int messageCount = acceptedMessages;
            final int ackCount = acceptedAcks;
            final int rejectedCount = rejected;
            final boolean failedStorage = storageError;
            runOnUiThread(() -> {
                if (!unlocked) return;
                StringBuilder status = new StringBuilder();
                if (messageCount > 0) status.append(messageCount).append(" authenticated message(s) accepted. ");
                if (ackCount > 0) status.append(ackCount).append(" message(s) confirmed as accepted by the recipient app. ");
                if (rejectedCount > 0) status.append(rejectedCount).append(" duplicate, stale, malformed, or unauthenticated packet(s) ignored. ");
                if (failedStorage) status.append("Storage failed; unprocessed packets remain queued when possible.");
                if (status.length() > 0) setMainStatus(status.toString().trim(), failedStorage || rejectedCount > 0);
                refreshMessages();
            });
        });
    }

    private boolean hasSendPermission() {
        return checkSelfPermission(Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED;
    }

    private void flushPendingAcks() {
        if (!unlocked || !hasSendPermission() || ResetGuard.resetting) return;
        ioExecutor.execute(() -> {
            try {
                JSONObject data = vaultStore.copyData();
                JSONArray acks = data.optJSONArray("acks");
                if (acks == null) return;
                long now = System.currentTimeMillis();
                for (int i = 0; i < acks.length(); i++) {
                    JSONObject ack = acks.optJSONObject(i);
                    if (ack == null) continue;
                    String id = ack.optString("id", "");
                    String state = transportStatus(id);
                    boolean retryable = state.equals("pending") || state.equals("prepared") || state.equals("submission_failed")
                            || (state.equals("send_requested") && now - transportStatusTime(id) > 120_000L);
                    if (retryable) transmitSavedAck(ack, false);
                }
            } catch (Exception ignored) { }
        });
    }

    private void transmitSavedAck(JSONObject ack, boolean force) {
        if (!hasSendPermission() || ResetGuard.resetting) return;
        String id = ack.optString("id", "");
        String packet = ack.optString("packet", "");
        String contactId = ack.optString("contactId", "");
        if (id.isEmpty() || packet.isEmpty()) return;
        String state = transportStatus(id);
        if (!force) {
            long age = System.currentTimeMillis() - transportStatusTime(id);
            boolean retryable = state.equals("pending") || state.equals("prepared") || state.equals("submission_failed")
                    || (state.equals("send_requested") && age > 120_000L);
            if (!retryable) return;
        }
        String destination;
        try {
            JSONObject data = vaultStore.copyData();
            JSONObject contact = findContactByIdInData(data, contactId);
            if (contact == null) return;
            destination = contact.getString("number");
        } catch (Exception locked) { return; }

        setTransportStatus(id, "prepared"); // crash before send -> startup can retry; packet is already persisted
        try {
            SmsTransport.sendOneSegment(this, destination, packet, id);
            setTransportStatusIfCurrent(id, "prepared", "send_requested");
        } catch (Exception failure) {
            setTransportStatus(id, "submission_failed");
        }
    }

    private JSONObject findAckForCounter(JSONObject data, String contactId, long counter) {
        JSONArray acks = data.optJSONArray("acks");
        if (acks == null) return null;
        for (int i = acks.length() - 1; i >= 0; i--) {
            JSONObject ack = acks.optJSONObject(i);
            if (ack != null && contactId.equals(ack.optString("contactId"))
                    && ack.optLong("ackForCounter", -1L) == counter) return ack;
        }
        return null;
    }

    private static boolean isValidUtf8(byte[] bytes) {
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
            return true;
        } catch (CharacterCodingException invalid) {
            return false;
        }
    }

    private static void trimAcks(JSONArray acks) {
        while (acks.length() > MAX_SAVED_MESSAGES) acks.remove(0);
    }

    private void showAddContactDialog() {
        if (!unlocked) return;
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(8), dp(20), dp(4));
        EditText name = field("Contact name", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
        EditText number = field("Contact number in international format, e.g. +31612345678", InputType.TYPE_CLASS_PHONE);
        EditText secret = field("Shared secret: exactly 64 hexadecimal characters", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        secret.setSingleLine(true);
        form.addView(name);
        form.addView(number);
        form.addView(secret);
        form.addView(spacer(6));
        TextView help = smallText("Generate a new 32-byte key for each contact relationship. Enter the identical key on both phones, and exchange it only through a trusted separate channel. Do not reuse keys.", COLOR_MUTED);
        form.addView(help);
        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        Button generate = button("Generate key", false);
        Button copy = button("Copy key", false);
        actions.addView(generate, new LinearLayout.LayoutParams(0, dp(46), 1f));
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(0, dp(46), 1f);
        cp.setMargins(dp(8), 0, 0, 0);
        actions.addView(copy, cp);
        form.addView(actions);
        generate.setOnClickListener(v -> {
            byte[] key = new byte[32];
            RANDOM.nextBytes(key);
            secret.setText(Hex.encode(key));
            Arrays.fill(key, (byte) 0);
        });
        copy.setOnClickListener(v -> {
            String value = secret.getText().toString().trim();
            if (!value.matches("(?i)[0-9a-f]{64}")) {
                Toast.makeText(this, "Generate or enter a valid 64-character key first.", Toast.LENGTH_SHORT).show();
                return;
            }
            ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (clipboard != null) {
                ClipData clip = ClipData.newPlainText("CipherSMS shared secret", value.toLowerCase());
                if (Build.VERSION.SDK_INT >= 33) {
                    try { clip.getDescription().getExtras().putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true); }
                    catch (RuntimeException ignored) { }
                }
                clipboard.setPrimaryClip(clip);
                Toast.makeText(this, "Copied. The clipboard is not a secure exchange channel.", Toast.LENGTH_LONG).show();
            }
        });

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Add trusted contact")
                .setView(form)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save contact", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String contactName = name.getText().toString().trim();
            String numberInput = number.getText().toString().trim();
            String keyInput = secret.getText().toString().trim();
            String canonical;
            try { canonical = PhoneNumbers.normalizeInternational(numberInput); }
            catch (Exception invalid) { number.setError("Use a valid international number starting with +"); return; }
            if (contactName.isEmpty() || contactName.length() > 64) { name.setError("Enter a name up to 64 characters"); return; }
            if (keyInput.matches("(?i)[0-9a-f]{64}") == false) { secret.setError("Exactly 64 hexadecimal characters are required"); return; }
            try {
                String local = vaultStore.localNumber();
                if (canonical.equals(local)) { number.setError("A contact cannot use your own number"); return; }
                JSONObject data = vaultStore.copyData();
                JSONArray existing = data.optJSONArray("contacts");
                if (existing != null) for (int i = 0; i < existing.length(); i++) {
                    JSONObject c = existing.optJSONObject(i);
                    if (c != null && canonical.equals(c.optString("number"))) {
                        number.setError("A contact already uses this number. Remove the old contact before re-keying.");
                        return;
                    }
                    if (c != null && keyInput.equalsIgnoreCase(c.optString("secretHex", ""))) {
                        secret.setError("Use a different random secret for every contact relationship.");
                        return;
                    }
                }
            } catch (Exception e) { Toast.makeText(this, "Vault is not available.", Toast.LENGTH_SHORT).show(); return; }

            byte[] keyBytes;
            try { keyBytes = Hex.decode(keyInput); }
            catch (Exception e) { secret.setError("Invalid key"); return; }
            if (keyBytes.length != 32) { Arrays.fill(keyBytes, (byte) 0); secret.setError("Key must be 32 bytes"); return; }
            String secretHex = Hex.encode(keyBytes);
            Arrays.fill(keyBytes, (byte) 0);
            dialog.dismiss();
            name.setText(""); number.setText(""); secret.setText("");
            ioExecutor.execute(() -> {
                try {
                    JSONObject data = vaultStore.copyData();
                    JSONArray contacts = data.optJSONArray("contacts");
                    if (contacts == null) { contacts = new JSONArray(); data.put("contacts", contacts); }
                    JSONObject c = new JSONObject();
                    c.put("id", UUID.randomUUID().toString());
                    c.put("name", contactName);
                    c.put("number", canonical);
                    c.put("secretHex", secretHex);
                    c.put("nextSendCounter", 0L);
                    c.put("receiveHighest", -1L);
                    c.put("receiveBitmap", 0L);
                    contacts.put(c);
                    vaultStore.saveData(data);
                    runOnUiThread(() -> {
                        if (!unlocked) return;
                        selectedContactId = c.optString("id");
                        showMainScreen("Contact added. Verify both phones have the same key and phone numbers before sending.");
                    });
                } catch (Exception error) {
                    runOnUiThread(() -> setMainStatus("Could not save contact in the encrypted vault.", true));
                }
            });
        }));
        dialog.show();
    }

    private void confirmRemoveSelectedContact() {
        if (selectedContactId == null) return;
        JSONObject contact = findContactById(selectedContactId, contactChoices);
        if (contact == null) return;
        String name = contact.optString("name", "this contact");
        new AlertDialog.Builder(this)
                .setTitle("Remove " + name + "?")
                .setMessage("This deletes this contact's shared secret and local message history from the app vault. It cannot be undone. Re-adding the same number requires a fresh secret exchanged securely by both people.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove", (dialog, which) -> {
                    String removeId = selectedContactId;
                    ioExecutor.execute(() -> {
                        try {
                            JSONObject data = vaultStore.copyData();
                            data.put("contacts", filteredArray(data.optJSONArray("contacts"), removeId, "id"));
                            data.put("messages", filteredArray(data.optJSONArray("messages"), removeId, "contactId"));
                            data.put("acks", filteredArray(data.optJSONArray("acks"), removeId, "contactId"));
                            vaultStore.saveData(data);
                            runOnUiThread(() -> {
                                if (!unlocked) return;
                                selectedContactId = null;
                                showMainScreen("Contact and its message history were removed from the vault.");
                            });
                        } catch (Exception error) {
                            runOnUiThread(() -> setMainStatus("Could not remove the contact from the encrypted vault.", true));
                        }
                    });
                }).show();
    }

    private void lockNow() {
        if (!unlocked) return;
        unlocked = false;
        autoLockedForBackground = true;
        clearSensitiveViews();
        ioExecutor.execute(() -> {
            if (vaultStore != null) vaultStore.lock();
            runOnUiThread(() -> showUnlockScreen("Vault locked."));
        });
    }

    private void clearSensitiveViews() {
        if (pendingReceiverRegistered) {
            try { unregisterReceiver(pendingUpdateReceiver); } catch (IllegalArgumentException ignored) { }
            pendingReceiverRegistered = false;
        }
        clearEditTexts(root);
        if (mainMessagesColumn != null) mainMessagesColumn.removeAllViews();
        if (root != null) root.removeAllViews();
        root = null;
        mainMessagesColumn = null;
        mainStatus = null;
        sizeMeter = null;
        composer = null;
        contactSpinner = null;
        sendButton = null;
        retryButton = null;
        contactChoices.clear();
    }

    private static void clearEditTexts(View view) {
        if (view == null) return;
        if (view instanceof EditText) {
            ((EditText) view).setText("");
        } else if (view instanceof android.view.ViewGroup) {
            android.view.ViewGroup group = (android.view.ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) clearEditTexts(group.getChildAt(i));
        }
    }

    private JSONObject filteredArray(JSONArray source, String id, String field) throws JSONException {
        JSONArray kept = new JSONArray();
        if (source == null) return kept;
        for (int i = 0; i < source.length(); i++) {
            JSONObject item = source.optJSONObject(i);
            if (item != null && !id.equals(item.optString(field))) kept.put(item);
        }
        return kept;
    }

    private static JSONObject findContactByIdInData(JSONObject data, String id) {
        if (id == null) return null;
        JSONArray contacts = data.optJSONArray("contacts");
        if (contacts == null) return null;
        for (int i = 0; i < contacts.length(); i++) {
            JSONObject contact = contacts.optJSONObject(i);
            if (contact != null && id.equals(contact.optString("id"))) return contact;
        }
        return null;
    }

    private static void trimMessages(JSONArray messages) {
        while (messages.length() > MAX_SAVED_MESSAGES) messages.remove(0);
    }

    private void setTransportStatus(String id, String status) {
        getSharedPreferences("sms_transport_status", MODE_PRIVATE).edit()
                .putString(id, status + "|" + System.currentTimeMillis()).apply();
    }

    private void setTransportStatusIfCurrent(String id, String expected, String next) {
        android.content.SharedPreferences prefs = getSharedPreferences("sms_transport_status", MODE_PRIVATE);
        String value = prefs.getString(id, null);
        if (value != null && value.startsWith(expected + "|")) {
            prefs.edit().putString(id, next + "|" + System.currentTimeMillis()).apply();
        }
    }

    private String transportStatus(String id) {
        String value = getSharedPreferences("sms_transport_status", MODE_PRIVATE).getString(id, null);
        if (value == null) return "pending";
        int separator = value.indexOf('|');
        return separator < 0 ? value : value.substring(0, separator);
    }

    private long transportStatusTime(String id) {
        String value = getSharedPreferences("sms_transport_status", MODE_PRIVATE).getString(id, null);
        if (value == null) return 0L;
        int separator = value.indexOf('|');
        if (separator < 0) return 0L;
        try { return Long.parseLong(value.substring(separator + 1)); }
        catch (NumberFormatException ignored) { return 0L; }
    }

    private String statusText(String status) {
        switch (status) {
            case "carrier_reports_delivered": return "Carrier reports delivery to the phone; this does not prove the app accepted or a person read it.";
            case "submitted_to_carrier": return "Sent from this device; recipient delivery is unconfirmed.";
            case "send_failed":
            case "submission_failed": return "Sending failed or was not confirmed. You can retry the exact same packet.";
            case "delivery_unconfirmed": return "Delivery report unavailable or failed. The recipient may still receive it.";
            case "send_requested": return "Sending request submitted; waiting for device result.";
            default: return "Saved encrypted packet; carrier delivery is unconfirmed.";
        }
    }

    private void pruneTransportStatuses() {
        // Keep only status values for message ids still present in the bounded vault history.
        try {
            JSONObject data = vaultStore.copyData();
            java.util.HashSet<String> keep = new java.util.HashSet<>();
            JSONArray messages = data.optJSONArray("messages");
            if (messages != null) for (int i = 0; i < messages.length(); i++) {
                JSONObject m = messages.optJSONObject(i);
                if (m != null) keep.add(m.optString("id"));
            }
            JSONArray acks = data.optJSONArray("acks");
            if (acks != null) for (int i = 0; i < acks.length(); i++) {
                JSONObject a = acks.optJSONObject(i);
                if (a != null) keep.add(a.optString("id"));
            }
            android.content.SharedPreferences prefs = getSharedPreferences("sms_transport_status", MODE_PRIVATE);
            android.content.SharedPreferences.Editor editor = prefs.edit();
            for (String key : prefs.getAll().keySet()) if (!keep.contains(key)) editor.remove(key);
            editor.apply();
        } catch (Exception ignored) { }
    }

    private void setMainStatus(String text, boolean error) {
        if (mainStatus != null) setStatus(mainStatus, text, error);
    }

    private static void setStatus(TextView view, String text, boolean error) {
        view.setText(text);
        view.setTextColor(error ? COLOR_DANGER : COLOR_MUTED);
    }

    private TextView title(String text, float size) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(COLOR_INK);
        view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private TextView body(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(14);
        view.setTextColor(COLOR_INK);
        view.setLineSpacing(dp(2), 1f);
        return view;
    }

    private TextView smallText(String text, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(12);
        view.setTextColor(color);
        view.setLineSpacing(dp(1), 1f);
        return view;
    }

    private TextView sectionLabel(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(13);
        view.setTextColor(COLOR_MUTED);
        view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private EditText field(String hint, int inputType) {
        EditText view = new EditText(this);
        view.setHint(hint);
        view.setInputType(inputType);
        view.setTextColor(COLOR_INK);
        view.setHintTextColor(COLOR_MUTED);
        view.setPadding(dp(12), dp(8), dp(12), dp(8));
        view.setSingleLine(true);
        view.setSaveEnabled(false);
        view.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        view.setMinHeight(dp(48));
        return view;
    }

    private Button button(String text, boolean primary) {
        Button button = new Button(this);
        button.setText(text);
        button.setAllCaps(false);
        button.setTextSize(14);
        button.setTextColor(primary ? Color.WHITE : COLOR_ACCENT);
        button.setBackground(round(primary ? COLOR_ACCENT : Color.rgb(231, 239, 250), 12));
        button.setPadding(dp(12), dp(2), dp(12), dp(2));
        return button;
    }

    private LinearLayout card() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dp(16), dp(16), dp(16), dp(16));
        layout.setBackground(round(COLOR_CARD, 16));
        return layout;
    }

    private View warningCard(String text) {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(14), dp(12), dp(14), dp(12));
        panel.setBackground(round(COLOR_WARNING, 12));
        TextView warning = body(text);
        warning.setTextColor(Color.rgb(109, 75, 13));
        panel.addView(warning);
        return panel;
    }

    private View spacer(int heightDp) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(1, dp(heightDp)));
        return view;
    }

    private GradientDrawable round(int color, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radiusDp));
        return drawable;
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }

    private static void clearChars(char[] chars) {
        if (chars != null) Arrays.fill(chars, '\0');
    }
}
