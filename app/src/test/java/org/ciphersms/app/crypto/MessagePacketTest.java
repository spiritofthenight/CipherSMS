package org.ciphersms.app.crypto;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.Assert.*;

public class MessagePacketTest {
    private static final String ALICE = "+31612345678";
    private static final String BOB = "+447700900123";

    @Test public void encryptDecryptRoundTrip() throws Exception {
        byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) secret[i] = (byte) i;
        byte[] text = "Hallo Bob, Grüße aus Amsterdam 🌷".getBytes(StandardCharsets.UTF_8);
        String packet = MessagePacket.encrypt(secret, ALICE, BOB, 7, text);
        MessagePacket.Decoded decoded = MessagePacket.decrypt(secret, ALICE, BOB, packet);
        assertEquals(7L, decoded.counter);
        assertEquals(MessagePacket.TYPE_MESSAGE, decoded.type);
        assertArrayEquals(text, decoded.plaintext);
    }


    @Test public void ackPacketRoundTripsWithDistinctType() throws Exception {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 23);
        byte[] acknowledgedCounter = java.nio.ByteBuffer.allocate(4).putInt(42).array();
        String packet = MessagePacket.encryptTyped(secret, ALICE, BOB, MessagePacket.TYPE_ACK, 11, acknowledgedCounter);
        MessagePacket.Decoded decoded = MessagePacket.decrypt(secret, ALICE, BOB, packet);
        assertEquals(MessagePacket.TYPE_ACK, decoded.type);
        assertEquals(11L, decoded.counter);
        assertArrayEquals(acknowledgedCounter, decoded.plaintext);
    }

    @Test public void freshNonceMakesPacketsDiffer() throws Exception {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 42);
        byte[] text = "same message".getBytes(StandardCharsets.UTF_8);
        String first = MessagePacket.encrypt(secret, ALICE, BOB, 9, text);
        String second = MessagePacket.encrypt(secret, ALICE, BOB, 9, text);
        assertNotEquals(first, second);
    }

    @Test public void ciphertextTamperingIsRejected() throws Exception {
        byte[] secret = new byte[32];
        byte[] text = "do not tamper".getBytes(StandardCharsets.UTF_8);
        String packet = MessagePacket.encrypt(secret, ALICE, BOB, 1, text);
        byte[] raw = Base64.getDecoder().decode(packet);
        raw[18] ^= 0x40;
        String tampered = Base64.getEncoder().encodeToString(raw);
        try {
            MessagePacket.decrypt(secret, ALICE, BOB, tampered);
            fail("Tampered packet was accepted");
        } catch (javax.crypto.AEADBadTagException expected) {
            // Expected: AES-GCM authentication rejected the modified packet.
        }
    }

    @Test public void wrongDirectionKeyIsRejected() throws Exception {
        byte[] secret = new byte[32];
        String packet = MessagePacket.encrypt(secret, ALICE, BOB, 2,
                "hello".getBytes(StandardCharsets.UTF_8));
        try {
            MessagePacket.decrypt(secret, BOB, ALICE, packet);
            fail("Reverse direction must use a different key/context");
        } catch (javax.crypto.AEADBadTagException expected) {
            // Expected.
        }
    }

    @Test public void actualPacketAtByteLimitIsOneSms() throws Exception {
        byte[] secret = new byte[32];
        byte[] message = new byte[87];
        Arrays.fill(message, (byte) 'A');
        String packet = MessagePacket.encrypt(secret, ALICE, BOB, 0, message);
        assertEquals(160, packet.length());
        assertTrue(MessagePacket.isTransportCandidate(packet));
        assertArrayEquals(message, MessagePacket.decrypt(secret, ALICE, BOB, packet).plaintext);
        try {
            MessagePacket.encrypt(secret, ALICE, BOB, 1, new byte[88]);
            fail("An 88-byte plaintext must not fit in one SMS");
        } catch (IllegalArgumentException expected) {
            // Correct: the protocol refuses to split or truncate.
        }
    }

    @Test public void maxSmsSizeIsByteAware() {
        assertTrue(MessagePacket.plaintextFitsSingleSms(87));
        assertEquals(160, MessagePacket.encodedLengthForPlaintextBytes(87));
        assertFalse(MessagePacket.plaintextFitsSingleSms(88));
        assertFalse(MessagePacket.textFitsSingleSms("🌷".repeat(22))); // 88 UTF-8 bytes
        byte[] candidate = new byte[33]; candidate[0] = (byte) 0x10;
        assertTrue(MessagePacket.isTransportCandidate(Base64.getEncoder().encodeToString(candidate)));
    }
}
