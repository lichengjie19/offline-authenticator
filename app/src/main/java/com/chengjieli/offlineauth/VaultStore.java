package com.chengjieli.offlineauth;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import android.util.JsonReader;
import android.util.JsonToken;

import com.chengjieli.offlineauth.core.Account;
import com.chengjieli.offlineauth.core.AccountTransfer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Authenticated, device-local storage. No account secrets are ever written in plaintext. */
public final class VaultStore {
    private static final String KEY_ALIAS = "offline_auth_vault_v1";
    private static final byte[] HEADER = new byte[]{'O', 'A', 'V', 1};
    private static final byte[] AAD = "OfflineAuthenticator:account-vault:v1"
            .getBytes(StandardCharsets.UTF_8);
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int MAX_FILE_BYTES = 1024 * 1024;
    private static final int MAX_ACCOUNTS = 250;
    private static final Object STORE_LOCK = new Object();

    private final File file;
    private final AtomicFile atomicFile;
    private final String keyAlias;

    public VaultStore(Context context) {
        this(new File(context.getNoBackupFilesDir(), "vault.bin"), KEY_ALIAS);
    }

    // Package-private so instrumentation tests never touch the production file or key.
    VaultStore(File file, String keyAlias) {
        if (file == null || keyAlias == null || keyAlias.isEmpty()) {
            throw new IllegalArgumentException("A vault file and key alias are required.");
        }
        this.file = file;
        this.atomicFile = new AtomicFile(file);
        this.keyAlias = keyAlias;
    }

    public synchronized List<Account> load() throws Exception {
        synchronized (STORE_LOCK) {
            if (!hasVaultFiles()) {
                return new ArrayList<>();
            }
            return readAccounts();
        }
    }

    /** Merge a portable backup without allowing another store instance to interleave a write. */
    public synchronized AccountTransfer.Result mergeAndSave(List<Account> imported) throws Exception {
        synchronized (STORE_LOCK) {
            AccountTransfer.Result result = AccountTransfer.merge(load(), imported);
            if (result.added > 0) save(result.accounts);
            return result;
        }
    }

    public synchronized void save(List<Account> accounts) throws Exception {
        synchronized (STORE_LOCK) {
            byte[] plaintext = serialize(accounts);
            try {
                boolean alreadyExists = hasVaultFiles();
                // A caller cannot overwrite an unreadable vault by catching load()'s error
                // and saving an empty list. Validate the existing vault before any write.
                if (alreadyExists) {
                    readAccounts();
                }
                SecretKey key = getKey(!alreadyExists);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                authenticateHeader(cipher);
                byte[] iv = cipher.getIV();
                if (iv == null || iv.length != IV_BYTES) {
                    throw new IOException("Unexpected encryption IV length.");
                }
                byte[] ciphertext = cipher.doFinal(plaintext);
                byte[] payload = ByteBuffer.allocate(HEADER.length + IV_BYTES + ciphertext.length)
                        .put(HEADER).put(iv).put(ciphertext).array();
                if (payload.length > MAX_FILE_BYTES) {
                    throw new IOException("Account vault exceeds the supported size.");
                }
                writeAtomically(payload);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    private List<Account> readAccounts() throws Exception {
        byte[] payload = readBounded();
        if (payload.length < HEADER.length + IV_BYTES + TAG_BITS / 8) {
            throw new IOException("The existing account vault is truncated; it was not replaced.");
        }
        for (int index = 0; index < HEADER.length; index++) {
            if (payload[index] != HEADER[index]) {
                throw new IOException("Unsupported or damaged account vault format.");
            }
        }
        // Never generate a replacement key when a vault already exists.
        SecretKey key = getKey(false);
        byte[] iv = Arrays.copyOfRange(payload, HEADER.length, HEADER.length + IV_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        authenticateHeader(cipher);
        byte[] plaintext;
        try {
            plaintext = cipher.doFinal(payload, HEADER.length + IV_BYTES,
                    payload.length - HEADER.length - IV_BYTES);
        } catch (Exception failure) {
            throw new IOException("The existing account vault cannot be authenticated; "
                    + "it was not replaced.", failure);
        }
        try {
            return deserialize(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static void authenticateHeader(Cipher cipher) {
        cipher.updateAAD(HEADER);
        cipher.updateAAD(AAD);
    }

    private SecretKey getKey(boolean createIfMissing) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyAlias)) {
            KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);
            if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                throw new IOException("The account vault encryption key is unavailable.");
            }
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        if (!createIfMissing) {
            throw new IOException("The account vault encryption key is missing; "
                    + "the existing vault was not replaced.");
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build());
        return generator.generateKey();
    }

    private boolean hasVaultFiles() {
        // AtomicFile uses .bak on older Android versions and .new on recent ones.
        return file.exists() || new File(file.getPath() + ".bak").exists()
                || new File(file.getPath() + ".new").exists();
    }

    private byte[] readBounded() throws IOException {
        try (FileInputStream input = atomicFile.openRead();
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int size;
            while ((size = input.read(buffer)) != -1) {
                if (output.size() > MAX_FILE_BYTES - size) {
                    throw new IOException("Account vault exceeds the supported size.");
                }
                output.write(buffer, 0, size);
            }
            return output.toByteArray();
        }
    }

    private void writeAtomically(byte[] payload) throws IOException {
        File parent = file.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new IOException("The private account storage directory is unavailable.");
        }
        FileOutputStream output = null;
        try {
            output = atomicFile.startWrite();
            output.write(payload);
            output.getFD().sync();
            atomicFile.finishWrite(output);
            output = null;
        } catch (IOException | RuntimeException failure) {
            if (output != null) {
                atomicFile.failWrite(output);
            }
            throw failure;
        }
        // AtomicFile.finishWrite() has no error result on some Android releases.
        // Read back the committed ciphertext before reporting a successful save.
        if (!Arrays.equals(payload, readBounded())) {
            throw new IOException("The account vault write could not be verified.");
        }
    }

    private static byte[] serialize(List<Account> accounts) throws Exception {
        if (accounts == null || accounts.size() > MAX_ACCOUNTS) {
            throw new IOException("The account list is missing or exceeds 250 entries.");
        }
        JSONArray rows = new JSONArray();
        Set<String> ids = new HashSet<>();
        for (Account account : accounts) {
            validateAccount(account, ids);
            JSONObject row = new JSONObject();
            row.put("id", account.id);
            row.put("issuer", account.issuer);
            row.put("name", account.name);
            row.put("secret", account.secret);
            row.put("algorithm", account.algorithm);
            row.put("digits", account.digits);
            row.put("period", account.period);
            rows.put(row);
        }
        JSONObject document = new JSONObject();
        document.put("version", 1);
        document.put("accounts", rows);
        byte[] bytes = document.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_FILE_BYTES - HEADER.length - IV_BYTES - TAG_BITS / 8) {
            Arrays.fill(bytes, (byte) 0);
            throw new IOException("Account vault exceeds the supported size.");
        }
        return bytes;
    }

    private static List<Account> deserialize(byte[] plaintext) throws Exception {
        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plaintext)).toString();
        } catch (CharacterCodingException failure) {
            throw new IOException("The account vault contains invalid text.", failure);
        }
        try {
            // Android's JSONObject parser accepts comments, unquoted names and duplicate
            // fields. Reject those before validating the versioned schema below.
            try (JsonReader reader = new JsonReader(new StringReader(json))) {
                reader.setLenient(false);
                validateStrictJson(reader, 0);
                if (reader.peek() != JsonToken.END_DOCUMENT) {
                    throw new JSONException("Trailing account vault content.");
                }
            }
            JSONTokener tokener = new JSONTokener(json);
            Object parsed = tokener.nextValue();
            if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) {
                throw new JSONException("Invalid account vault document.");
            }
            JSONObject document = (JSONObject) parsed;
            requireKeys(document, "version", "accounts");
            if (requireInteger(document, "version") != 1) {
                throw new JSONException("Unsupported account vault schema.");
            }
            Object rawRows = document.get("accounts");
            if (!(rawRows instanceof JSONArray)) {
                throw new JSONException("The account list must be an array.");
            }
            JSONArray rows = (JSONArray) rawRows;
            if (rows.length() > MAX_ACCOUNTS) {
                throw new JSONException("Too many accounts in the account vault.");
            }
            List<Account> accounts = new ArrayList<>(rows.length());
            Set<String> ids = new HashSet<>();
            for (int index = 0; index < rows.length(); index++) {
                Object rawRow = rows.get(index);
                if (!(rawRow instanceof JSONObject)) {
                    throw new JSONException("An account must be an object.");
                }
                JSONObject row = (JSONObject) rawRow;
                requireKeys(row, "id", "issuer", "name", "secret", "algorithm", "digits", "period");
                Account account = new Account(requireString(row, "id", 128),
                        requireString(row, "issuer", 256), requireString(row, "name", 256),
                        requireString(row, "secret", 1024), requireString(row, "algorithm", 16),
                        requireInteger(row, "digits"), requireInteger(row, "period"));
                validateAccount(account, ids);
                accounts.add(account);
            }
            return accounts;
        } catch (JSONException | IllegalArgumentException failure) {
            throw new IOException("The account vault schema is invalid; it was not replaced.", failure);
        }
    }

    private static void validateStrictJson(JsonReader reader, int depth) throws Exception {
        if (depth > 3) {
            throw new JSONException("Unexpected account vault nesting.");
        }
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                reader.beginObject();
                Set<String> names = new HashSet<>();
                while (reader.hasNext()) {
                    if (!names.add(reader.nextName()) || names.size() > 7) {
                        throw new JSONException("Duplicate or excessive account vault fields.");
                    }
                    validateStrictJson(reader, depth + 1);
                }
                reader.endObject();
                break;
            case BEGIN_ARRAY:
                reader.beginArray();
                int count = 0;
                while (reader.hasNext()) {
                    if (++count > MAX_ACCOUNTS) {
                        throw new JSONException("Too many entries in the account vault.");
                    }
                    validateStrictJson(reader, depth + 1);
                }
                reader.endArray();
                break;
            case STRING:
                if (reader.nextString().length() > 1024) {
                    throw new JSONException("Account vault string exceeds the supported size.");
                }
                break;
            case NUMBER:
                String number = reader.nextString();
                if (!number.matches("-?(0|[1-9][0-9]*)")) {
                    throw new JSONException("Account vault fields must use integer numbers.");
                }
                break;
            default:
                throw new JSONException("Unexpected account vault value type.");
        }
    }

    private static void validateAccount(Account account, Set<String> ids) throws IOException {
        if (account == null || account.id == null || account.id.isEmpty()
                || account.id.length() > 128 || account.issuer == null
                || account.issuer.length() > 256 || account.name == null
                || account.name.length() > 256 || account.secret == null
                || account.secret.length() > 1024 || account.algorithm == null
                || account.algorithm.length() > 16 || !ids.add(account.id)) {
            throw new IOException("The account list contains an invalid or duplicate entry.");
        }
        // The core model validates Base32, supported algorithms, digits and periods.
        try {
            new Account(account.id, account.issuer, account.name, account.secret,
                    account.algorithm, account.digits, account.period);
        } catch (IllegalArgumentException failure) {
            throw new IOException("The account list contains unsupported parameters.", failure);
        }
    }

    private static String requireString(JSONObject object, String key, int maxLength)
            throws JSONException {
        Object value = object.get(key);
        if (!(value instanceof String) || ((String) value).length() > maxLength) {
            throw new JSONException("Invalid account string field: " + key);
        }
        return (String) value;
    }

    private static int requireInteger(JSONObject object, String key) throws JSONException {
        Object value = object.get(key);
        if (!(value instanceof Integer)) {
            throw new JSONException("Invalid account integer field: " + key);
        }
        return (Integer) value;
    }

    private static void requireKeys(JSONObject object, String... expected) throws JSONException {
        Set<String> keys = new HashSet<>(Arrays.asList(expected));
        if (object.length() != keys.size()) {
            throw new JSONException("Unexpected account vault fields.");
        }
        Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) {
            if (!keys.remove(iterator.next())) {
                throw new JSONException("Unexpected account vault field.");
            }
        }
        if (!keys.isEmpty()) {
            throw new JSONException("Missing account vault fields.");
        }
    }
}
