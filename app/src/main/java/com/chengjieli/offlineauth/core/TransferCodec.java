package com.chengjieli.offlineauth.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

/**
 * Portable password-protected backup, independent of Android Keystore.
 *
 * Version 1, big-endian: magic[8] "OATBACK\\0", u16 version=1, u8 kdf=1,
 * u8 cipher=1, i32 iterations=600000, u8 saltLength=16, u8 ivLength=12,
 * i32 ciphertextLength, salt[16], iv[12], ciphertext including 16-byte GCM tag.
 * All 50 header bytes are GCM AAD. KDF 1 is PBKDF2-HMAC-SHA256 (256 bits);
 * cipher 1 is AES-256-GCM. Version 1 accepts only the exact parameter set above.
 * Plaintext: i32 accountCount; for each account, five UTF-8 strings (id, issuer,
 * name, secret, algorithm), each prefixed by i32 byte length; i32 digits, i32 period.
 * No trailing bytes, unknown fields or optional structures are accepted.
 */
public final class TransferCodec {
    public static final int MAX_FILE_BYTES = 1024 * 1024;
    public static final int MAX_ACCOUNTS = 250;
    private static final byte[] MAGIC = {'O', 'A', 'T', 'B', 'A', 'C', 'K', 0};
    private static final int VERSION = 1;
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int HEADER_BYTES = 50;
    private static final SecureRandom RANDOM = new SecureRandom();

    private TransferCodec() { }

    public static byte[] encrypt(List<Account> accounts, char[] password)
            throws IOException, GeneralSecurityException {
        validatePassword(password);
        byte[] plaintext = serialize(accounts);
        byte[] keyBytes = null;
        try {
            byte[] salt = new byte[SALT_BYTES];
            byte[] iv = new byte[IV_BYTES];
            RANDOM.nextBytes(salt);
            RANDOM.nextBytes(iv);
            byte[] header = makeHeader(salt, iv, plaintext.length + TAG_BYTES);
            keyBytes = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, iv));
            cipher.updateAAD(header);
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] result = new byte[header.length + ciphertext.length];
            System.arraycopy(header, 0, result, 0, header.length);
            System.arraycopy(ciphertext, 0, result, header.length, ciphertext.length);
            return result;
        } catch (GeneralSecurityException failure) {
            throw new GeneralSecurityException("设备暂不支持备份加密");
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public static List<Account> decrypt(byte[] encrypted, char[] password)
            throws IOException, GeneralSecurityException {
        validatePassword(password);
        if (encrypted == null || encrypted.length < HEADER_BYTES + TAG_BYTES + 4
                || encrypted.length > MAX_FILE_BYTES) {
            throw invalidFormat();
        }
        byte[] header = Arrays.copyOf(encrypted, HEADER_BYTES);
        Header parameters = readHeader(header, encrypted.length);
        byte[] keyBytes = null;
        byte[] plaintext = null;
        try {
            keyBytes = deriveKey(password, parameters.salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, parameters.iv));
            cipher.updateAAD(header);
            plaintext = cipher.doFinal(encrypted, HEADER_BYTES, encrypted.length - HEADER_BYTES);
            return deserialize(plaintext);
        } catch (GeneralSecurityException failure) {
            // A wrong password and authenticated-data corruption intentionally share one error.
            throw new GeneralSecurityException("密码错误或备份文件已损坏");
        } finally {
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, ITERATIONS, 256);
        SecretKey generated = null;
        byte[] encoded = null;
        try {
            generated = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification);
            encoded = generated.getEncoded();
            if (encoded == null || encoded.length != 32) {
                throw new GeneralSecurityException("无法派生备份密钥");
            }
            return encoded.clone();
        } finally {
            specification.clearPassword();
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
            if (generated != null) {
                try { generated.destroy(); }
                catch (DestroyFailedException ignored) { /* Some JCA providers do not implement destruction. */ }
            }
        }
    }

    private static void validatePassword(char[] password) {
        if (password == null || password.length < 8 || password.length > 256) {
            throw new IllegalArgumentException("备份密码长度必须为 8 至 256 个字符");
        }
    }

    private static byte[] makeHeader(byte[] salt, byte[] iv, int ciphertextLength) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(HEADER_BYTES);
        DataOutputStream output = new DataOutputStream(bytes);
        output.write(MAGIC);
        output.writeShort(VERSION);
        output.writeByte(1);
        output.writeByte(1);
        output.writeInt(ITERATIONS);
        output.writeByte(SALT_BYTES);
        output.writeByte(IV_BYTES);
        output.writeInt(ciphertextLength);
        output.write(salt);
        output.write(iv);
        output.flush();
        return bytes.toByteArray();
    }

    private static Header readHeader(byte[] header, int fileLength) throws IOException {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(header));
        byte[] magic = new byte[MAGIC.length];
        input.readFully(magic);
        if (!Arrays.equals(MAGIC, magic) || input.readUnsignedShort() != VERSION
                || input.readUnsignedByte() != 1 || input.readUnsignedByte() != 1
                || input.readInt() != ITERATIONS || input.readUnsignedByte() != SALT_BYTES
                || input.readUnsignedByte() != IV_BYTES
                || input.readInt() != fileLength - HEADER_BYTES) {
            // Validate KDF cost and every structural length before running PBKDF2 or allocating payloads.
            throw invalidFormat();
        }
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        input.readFully(salt);
        input.readFully(iv);
        return new Header(salt, iv);
    }

    private static byte[] serialize(List<Account> accounts) throws IOException {
        if (accounts == null || accounts.size() > MAX_ACCOUNTS) {
            throw new IllegalArgumentException("备份最多支持 250 个账号");
        }
        WipingOutputStream bytes = new WipingOutputStream();
        try {
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(accounts.size());
            for (Account account : accounts) {
                if (account == null) throw new IllegalArgumentException("备份中存在无效账号");
                writeString(output, account.id);
                writeString(output, account.issuer);
                writeString(output, account.name);
                writeString(output, account.secret);
                writeString(output, account.algorithm);
                output.writeInt(account.digits);
                output.writeInt(account.period);
                if (bytes.size() > MAX_FILE_BYTES - HEADER_BYTES - TAG_BYTES) {
                    throw new IllegalArgumentException("备份文件超过 1 MiB 限制");
                }
            }
            output.flush();
            return bytes.toByteArray();
        } finally {
            bytes.wipe();
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            output.writeInt(encoded.length);
            output.write(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static List<Account> deserialize(byte[] plaintext) throws IOException {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext));
        int count = input.readInt();
        if (count < 0 || count > MAX_ACCOUNTS) throw invalidFormat();
        List<Account> accounts = new ArrayList<>(count);
        try {
            for (int index = 0; index < count; index++) {
                String id = readString(input, 512);
                String issuer = readString(input, 1024);
                String name = readString(input, 1024);
                String secret = readString(input, 208);
                String algorithm = readString(input, 16);
                int digits = input.readInt();
                int period = input.readInt();
                accounts.add(new Account(id, issuer, name, secret, algorithm, digits, period));
            }
            if (input.available() != 0) throw invalidFormat();
            return accounts;
        } catch (IllegalArgumentException failure) {
            throw new IOException("备份中的账号数据无效");
        }
    }

    private static String readString(DataInputStream input, int maxBytes) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maxBytes || length > input.available()) throw invalidFormat();
        byte[] encoded = new byte[length];
        try {
            input.readFully(encoded);
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString();
        } catch (CharacterCodingException failure) {
            throw invalidFormat();
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static IOException invalidFormat() {
        return new IOException("备份格式不受支持或文件已损坏");
    }

    private static final class Header {
        final byte[] salt;
        final byte[] iv;
        Header(byte[] salt, byte[] iv) { this.salt = salt; this.iv = iv; }
    }

    private static final class WipingOutputStream extends ByteArrayOutputStream {
        void wipe() { Arrays.fill(buf, (byte) 0); reset(); }
    }
}
