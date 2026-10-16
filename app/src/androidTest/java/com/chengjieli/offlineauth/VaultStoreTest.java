package com.chengjieli.offlineauth;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.chengjieli.offlineauth.core.Account;
import com.chengjieli.offlineauth.core.AccountTransfer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** These tests use a unique vault AND Keystore alias, never a user's account vault. */
@RunWith(AndroidJUnit4.class)
public final class VaultStoreTest {
    private File directory;
    private File vaultFile;
    private String alias;
    private VaultStore store;

    @Before
    public void setUp() throws Exception {
        String unique = UUID.randomUUID().toString();
        directory = new File(InstrumentationRegistry.getInstrumentation().getTargetContext()
                .getNoBackupFilesDir(), "vault-test-" + unique);
        assertTrue(directory.mkdirs());
        vaultFile = new File(directory, "vault.bin");
        alias = "offline_auth_test_" + unique;
        store = new VaultStore(vaultFile, alias);
    }

    @After
    public void tearDown() throws Exception {
        try {
            if (alias != null) {
                keyStore().deleteEntry(alias);
            }
        } finally {
            deleteRecursively(directory);
        }
    }

    @Test
    public void testNewVaultIsEmptyWithoutCreatingAKey() throws Exception {
        assertEquals(0, store.load().size());
        assertFalse(vaultFile.exists());
        assertFalse(keyStore().containsAlias(alias));
        store.save(new ArrayList<>());
        assertTrue(vaultFile.isFile());
        assertTrue(keyStore().containsAlias(alias));
        assertEquals(0, new VaultStore(vaultFile, alias).load().size());
    }

    @Test
    public void testMultipleAccountsSurviveNewStoreInstance() throws Exception {
        List<Account> expected = sampleAccounts();
        store.save(expected);
        List<Account> actual = new VaultStore(vaultFile, alias).load();
        assertEquals(expected.size(), actual.size());
        for (int index = 0; index < expected.size(); index++) {
            assertAccountEquals(expected.get(index), actual.get(index));
        }
    }

    @Test
    public void testCiphertextContainsNoPlaintextAndUsesFreshIv() throws Exception {
        List<Account> accounts = sampleAccounts();
        store.save(accounts);
        byte[] first = readRaw();
        String raw = new String(first, StandardCharsets.ISO_8859_1);
        for (Account account : accounts) {
            assertFalse(raw.contains(account.secret));
            assertFalse(raw.contains(account.name));
            assertFalse(raw.contains(account.issuer));
        }
        assertFalse(raw.contains("\"accounts\""));
        store.save(accounts);
        byte[] second = readRaw();
        assertFalse("Each encryption needs a fresh IV.", Arrays.equals(first, second));
        assertEquals(accounts.size(), store.load().size());
    }

    @Test
    public void testTamperingRejectsLoadAndSaveAndPreservesOriginalFile() throws Exception {
        store.save(sampleAccounts());
        byte[] tampered = readRaw();
        tampered[tampered.length - 1] ^= 0x40;
        writeRaw(tampered);

        assertFails(() -> store.load());
        assertTrue(Arrays.equals(tampered, readRaw()));
        assertFails(() -> store.save(new ArrayList<>()));
        assertTrue("A failed load must never allow an empty overwrite.",
                Arrays.equals(tampered, readRaw()));
    }

    @Test
    public void testMissingKeyIsNotRegeneratedAndOriginalFileIsPreserved() throws Exception {
        store.save(sampleAccounts());
        byte[] encrypted = readRaw();
        keyStore().deleteEntry(alias);

        assertFails(() -> store.load());
        assertFails(() -> store.save(new ArrayList<>()));
        assertFalse("A missing key must not be silently regenerated.",
                keyStore().containsAlias(alias));
        assertTrue(Arrays.equals(encrypted, readRaw()));
    }

    @Test
    public void testExistingEmptyFileIsCorruptionRatherThanAnEmptyAccountList() throws Exception {
        writeRaw(new byte[0]);
        assertFails(() -> store.load());
        assertFails(() -> store.save(new ArrayList<>()));
        assertEquals(0L, vaultFile.length());
        assertFalse(keyStore().containsAlias(alias));
    }

    @Test
    public void testTruncatedFileIsPreserved() throws Exception {
        store.save(sampleAccounts());
        byte[] truncated = Arrays.copyOf(readRaw(), 12);
        writeRaw(truncated);
        assertFails(() -> store.load());
        assertFails(() -> store.save(sampleAccounts()));
        assertTrue(Arrays.equals(truncated, readRaw()));
    }

    @Test
    public void testOversizedFileIsRejectedWithoutReplacement() throws Exception {
        byte[] oversized = new byte[1024 * 1024 + 1];
        Arrays.fill(oversized, (byte) 0x7f);
        writeRaw(oversized);
        assertFails(() -> store.load());
        assertFails(() -> store.save(new ArrayList<>()));
        assertEquals(oversized.length, vaultFile.length());
        assertTrue(Arrays.equals(oversized, readRaw()));
        assertFalse(keyStore().containsAlias(alias));
    }

    @Test
    public void testDuplicateIdsCannotOverwriteValidVault() throws Exception {
        List<Account> accounts = sampleAccounts();
        store.save(accounts);
        byte[] encrypted = readRaw();
        List<Account> duplicate = Arrays.asList(accounts.get(0), accounts.get(0));
        assertFails(() -> store.save(duplicate));
        assertTrue(Arrays.equals(encrypted, readRaw()));
        assertEquals(accounts.size(), store.load().size());
    }

    @Test
    public void testTransferMergeUsesLatestVaultAndPreservesExistingNames() throws Exception {
        List<Account> samples = sampleAccounts();
        store.save(Arrays.asList(samples.get(0)));
        // A different store instance adds an account after a transfer preview was calculated.
        new VaultStore(vaultFile, alias).save(Arrays.asList(samples.get(0), samples.get(1)));
        Account old = samples.get(0);
        Account duplicate = new Account("imported-id", "Imported name", "imported@example.test",
                old.secret, old.algorithm, old.digits, old.period);
        AccountTransfer.Result result = store.mergeAndSave(Arrays.asList(duplicate, samples.get(2)));
        assertEquals(1, result.added);
        assertEquals(1, result.skipped);
        assertEquals(3, store.load().size());
        assertAccountEquals(old, store.load().get(0));
        assertAccountEquals(samples.get(1), store.load().get(1));
        byte[] saved = readRaw();
        AccountTransfer.Result repeated = store.mergeAndSave(Arrays.asList(duplicate, samples.get(2)));
        assertEquals(0, repeated.added);
        assertEquals(2, repeated.skipped);
        assertTrue(Arrays.equals(saved, readRaw()));
    }

    @Test
    public void testInterruptedWriteBackupCanBeRecovered() throws Exception {
        store.save(sampleAccounts());
        byte[] encrypted = readRaw();
        assertTrue(vaultFile.renameTo(new File(vaultFile.getPath() + ".bak")));
        writeRaw(new byte[]{1, 2, 3});
        assertEquals(3, store.load().size());
        assertTrue(Arrays.equals(encrypted, readRaw()));
    }

    @Test
    public void testAuthenticatedMalformedSchemaIsRejectedWithoutReplacement() throws Exception {
        store.save(sampleAccounts());
        String row = "{\"id\":\"fixture-account\",\"issuer\":\"Example\","
                + "\"name\":\"fixture@example.test\","
                + "\"secret\":\"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\","
                + "\"algorithm\":\"SHA1\",\"digits\":6,\"period\":30}";
        String valid = "{\"version\":1,\"accounts\":[" + row + "]}";
        String[] invalidDocuments = {
                valid.replace("\"version\":1", "\"version\":2"),
                valid.replace("\"version\":1", "\"version\":\"1\""),
                valid.replace("\"version\":1", "\"version\":1.0"),
                valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
                valid.replace("\"version\":1", "\"version\":1,\"extra\":1"),
                valid.replace("\"period\":30", "\"period\":\"30\""),
                valid.replace(",\"period\":30", ""),
                valid.replace("\"digits\":6", "\"digits\":7"),
                valid.replace("\"version\"", "version"),
                valid + " {}",
                "{\"version\":1,\"accounts\":{}}",
                "{\"version\":1,\"accounts\":[null]}",
                "{\"version\":1,\"accounts\":[" + row + "," + row + "]}"
        };
        for (String invalid : invalidDocuments) {
            writeAuthenticatedFixture(invalid);
            byte[] original = readRaw();
            assertFails(() -> store.load());
            assertFails(() -> store.save(new ArrayList<>()));
            assertTrue(Arrays.equals(original, readRaw()));
        }
    }

    private static List<Account> sampleAccounts() {
        String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        return Arrays.asList(
                new Account("11111111-1111-4111-8111-111111111111", "Example GitHub",
                        "person@example.test", secret, "SHA1", 6, 30),
                new Account("22222222-2222-4222-8222-222222222222", "Example Microsoft",
                        "work@example.test", secret, "SHA256", 8, 60),
                new Account("33333333-3333-4333-8333-333333333333", "测试机构",
                        "本地测试账号", secret, "SHA512", 6, 15));
    }

    private static void assertAccountEquals(Account expected, Account actual) {
        assertEquals(expected.id, actual.id);
        assertEquals(expected.issuer, actual.issuer);
        assertEquals(expected.name, actual.name);
        assertEquals(expected.secret, actual.secret);
        assertEquals(expected.algorithm, actual.algorithm);
        assertEquals(expected.digits, actual.digits);
        assertEquals(expected.period, actual.period);
    }

    private byte[] readRaw() throws Exception {
        try (FileInputStream input = new FileInputStream(vaultFile);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int size;
            while ((size = input.read(buffer)) != -1) {
                output.write(buffer, 0, size);
            }
            return output.toByteArray();
        }
    }

    private void writeRaw(byte[] bytes) throws Exception {
        try (FileOutputStream output = new FileOutputStream(vaultFile)) {
            output.write(bytes);
            output.getFD().sync();
        }
    }

    private void writeAuthenticatedFixture(String json) throws Exception {
        SecretKey key = ((KeyStore.SecretKeyEntry) keyStore().getEntry(alias, null))
                .getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] header = new byte[]{'O', 'A', 'V', 1};
        cipher.updateAAD(header);
        cipher.updateAAD("OfflineAuthenticator:account-vault:v1".getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));
        writeRaw(ByteBuffer.allocate(4 + 12 + ciphertext.length)
                .put(header).put(cipher.getIV()).put(ciphertext).array());
    }

    private static KeyStore keyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return keyStore;
    }

    private static void assertFails(ThrowingAction action) throws Exception {
        try {
            action.run();
            fail("Expected the invalid vault operation to fail.");
        } catch (java.io.IOException expected) {
            // The caller gets an explicit error; no empty-vault fallback is permitted.
        }
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static void deleteRecursively(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        file.delete();
    }
}
