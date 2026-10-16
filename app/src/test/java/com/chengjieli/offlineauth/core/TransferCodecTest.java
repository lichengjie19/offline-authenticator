package com.chengjieli.offlineauth.core;

import static com.chengjieli.offlineauth.core.TotpTest.SHA1_SECRET;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.BeforeClass;
import org.junit.Test;

public class TransferCodecTest {
    private static final char[] PASSWORD = "公开测试密码+password-2026".toCharArray();
    private static final String SECOND_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    private static byte[] fixture;
    private static List<Account> source;

    @BeforeClass public static void createEncryptedFixture() throws Exception {
        source = Arrays.asList(
                new Account("first-id", "GitHub", "test@example.com", SHA1_SECRET, "SHA1", 6, 30),
                new Account("second-id", "测试 + 服务🔑", "张三+qa@example.com", SECOND_SECRET, "SHA256", 8, 60));
        fixture = TransferCodec.encrypt(source, PASSWORD);
    }

    @Test public void roundTripPreservesEveryFieldAndDoesNotMutatePassword() throws Exception {
        char[] input = PASSWORD.clone();
        byte[] originalFile = fixture.clone();
        List<Account> restored = TransferCodec.decrypt(fixture, input);
        assertEquals(source.size(), restored.size());
        for (int i = 0; i < source.size(); i++) assertSameAccount(source.get(i), restored.get(i));
        assertArrayEquals(PASSWORD, input);
        assertArrayEquals(originalFile, fixture);
        assertTrue(fixture.length <= TransferCodec.MAX_FILE_BYTES);
        assertFalse(new String(fixture, StandardCharsets.ISO_8859_1).contains(SHA1_SECRET));
    }

    @Test public void eachExportHasFreshSaltAndIvAndPreservesCallerPassword() throws Exception {
        char[] input = PASSWORD.clone();
        byte[] second = TransferCodec.encrypt(source, input);
        assertArrayEquals(PASSWORD, input);
        assertFalse(Arrays.equals(fixture, second));
        assertFalse(Arrays.equals(Arrays.copyOfRange(fixture, 22, 38), Arrays.copyOfRange(second, 22, 38)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(fixture, 38, 50), Arrays.copyOfRange(second, 38, 50)));
    }

    @Test public void emptyAndMaximumSizedAccountListsRoundTrip() throws Exception {
        assertTrue(TransferCodec.decrypt(TransferCodec.encrypt(Collections.emptyList(), PASSWORD), PASSWORD).isEmpty());
        List<Account> maximum = new ArrayList<>();
        for (int i = 0; i < 250; i++) {
            maximum.add(new Account("id-" + i, "Example", "user-" + i, SHA1_SECRET, "SHA1", 6, 30));
        }
        List<Account> restored = TransferCodec.decrypt(TransferCodec.encrypt(maximum, PASSWORD), PASSWORD);
        assertEquals(250, restored.size());
        assertSameAccount(maximum.get(249), restored.get(249));
    }

    @Test public void wrongPasswordAndCiphertextSaltOrIvTamperingFailAuthentication() throws Exception {
        char[] wrong = "wrong-test-password".toCharArray();
        char[] unchanged = wrong.clone();
        expectAuthenticationFailure(fixture, wrong);
        assertArrayEquals(unchanged, wrong);
        for (int offset : new int[]{22, 38, 50, fixture.length - 1}) {
            byte[] altered = fixture.clone();
            altered[offset] ^= 1;
            expectAuthenticationFailure(altered, PASSWORD);
        }
    }

    @Test public void rejectsUnknownVersionAlgorithmsLengthsAndMaliciousKdfBeforeDecrypting() throws Exception {
        for (int offset : new int[]{0, 8, 9, 10, 11, 16, 17, 18, 21}) {
            byte[] altered = fixture.clone();
            altered[offset] ^= 1;
            expectFormatFailure(altered);
        }
        for (int iterations : new int[]{0, -1, 599_999, 600_001, Integer.MAX_VALUE}) {
            byte[] altered = fixture.clone();
            ByteBuffer.wrap(altered).putInt(12, iterations);
            expectFormatFailure(altered);
        }
        expectFormatFailure(null);
        expectFormatFailure(new byte[0]);
        expectFormatFailure(Arrays.copyOf(fixture, 49));
        expectFormatFailure(Arrays.copyOf(fixture, fixture.length - 1));
        expectFormatFailure(Arrays.copyOf(fixture, fixture.length + 1));
        expectFormatFailure(new byte[TransferCodec.MAX_FILE_BYTES + 1]);
    }

    @Test public void rejectsInvalidPasswordsAndTooManyAccountsWithoutMutatingInputs() throws Exception {
        for (char[] invalid : new char[][]{null, new char[0], new char[7], new char[257]}) {
            expectIllegal(() -> TransferCodec.encrypt(source, invalid));
            expectIllegal(() -> TransferCodec.decrypt(fixture, invalid));
        }
        expectIllegal(() -> TransferCodec.encrypt(null, PASSWORD));
        expectIllegal(() -> TransferCodec.encrypt(Arrays.asList(source.get(0), null), PASSWORD));
        List<Account> tooMany = new ArrayList<>(Collections.nCopies(251, source.get(0)));
        expectIllegal(() -> TransferCodec.encrypt(tooMany, PASSWORD));
        assertEquals(251, tooMany.size());
    }

    @Test public void rejectsAuthenticatedButMalformedPlaintext() throws Exception {
        List<byte[]> malformed = new ArrayList<>();
        malformed.add(ByteBuffer.allocate(4).putInt(-1).array());
        malformed.add(ByteBuffer.allocate(4).putInt(251).array());
        malformed.add(ByteBuffer.allocate(5).putInt(0).put((byte) 1).array());
        malformed.add(ByteBuffer.allocate(8).putInt(1).putInt(Integer.MAX_VALUE).array());
        malformed.add(ByteBuffer.allocate(10).putInt(1).putInt(2).put((byte) 0xc0).put((byte) 0xaf).array());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(1);
        for (String field : new String[]{"id", "Example", "alice", "AAAA", "SHA1"}) {
            byte[] encoded = field.getBytes(StandardCharsets.UTF_8);
            output.writeInt(encoded.length);
            output.write(encoded);
        }
        output.writeInt(6);
        output.writeInt(30);
        malformed.add(bytes.toByteArray());

        // Reuse a public test-only derivation; each forged fixture gets a fresh random IV.
        byte[] salt = Arrays.copyOfRange(fixture, 22, 38);
        PBEKeySpec spec = new PBEKeySpec(PASSWORD, salt, 600_000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        spec.clearPassword();
        try {
            for (byte[] plaintext : malformed) {
                expectFormatFailure(encryptTestPayload(plaintext, key));
            }
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] encryptTestPayload(byte[] plaintext, byte[] key) throws Exception {
        byte[] header = Arrays.copyOf(fixture, 50);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        System.arraycopy(iv, 0, header, 38, 12);
        ByteBuffer.wrap(header).putInt(18, plaintext.length + 16);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD(header);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] encrypted = Arrays.copyOf(header, header.length + ciphertext.length);
        System.arraycopy(ciphertext, 0, encrypted, header.length, ciphertext.length);
        return encrypted;
    }

    private static void assertSameAccount(Account expected, Account actual) {
        assertEquals(expected.id, actual.id);
        assertEquals(expected.issuer, actual.issuer);
        assertEquals(expected.name, actual.name);
        assertEquals(expected.secret, actual.secret);
        assertEquals(expected.algorithm, actual.algorithm);
        assertEquals(expected.digits, actual.digits);
        assertEquals(expected.period, actual.period);
    }

    private static void expectAuthenticationFailure(byte[] input, char[] password) throws Exception {
        try {
            TransferCodec.decrypt(input, password);
            fail("Expected authentication failure");
        } catch (GeneralSecurityException expected) {
            assertEquals("密码错误或备份文件已损坏", expected.getMessage());
            assertEquals(null, expected.getCause());
        }
    }

    private static void expectFormatFailure(byte[] input) throws Exception {
        try {
            TransferCodec.decrypt(input, PASSWORD);
            fail("Expected malformed backup rejection");
        } catch (IOException expected) {
            assertFalse(String.valueOf(expected.getMessage()).contains(SHA1_SECRET));
            assertEquals(null, expected.getCause());
        }
    }

    private static void expectIllegal(CheckedOperation operation) throws Exception {
        try {
            operation.run();
            fail("Expected invalid parameter rejection");
        } catch (IllegalArgumentException expected) {
            assertFalse(String.valueOf(expected.getMessage()).contains(SHA1_SECRET));
        }
    }

    private interface CheckedOperation { void run() throws Exception; }
}
