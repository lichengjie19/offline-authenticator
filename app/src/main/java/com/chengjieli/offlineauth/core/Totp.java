package com.chengjieli.offlineauth.core;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 6238 TOTP with RFC 4226 dynamic truncation. */
public final class Totp {
    private Totp() { }

    public static String generate(Account account, long unixSeconds) {
        checkInputs(account, unixSeconds);
        long counter = unixSeconds / account.period;
        byte[] message = new byte[8];
        for (int i = 7; i >= 0; i--) {
            message[i] = (byte) (counter & 0xff);
            counter >>>= 8;
        }
        byte[] key = decodeBase32(account.secret);
        byte[] hash = null;
        try {
            String hmacAlgorithm = "Hmac" + account.algorithm;
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(new SecretKeySpec(key, hmacAlgorithm));
            hash = mac.doFinal(message);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            int modulus = account.digits == 8 ? 100_000_000 : 1_000_000;
            String number = Integer.toString(binary % modulus);
            StringBuilder result = new StringBuilder(account.digits);
            for (int i = number.length(); i < account.digits; i++) {
                result.append('0');
            }
            return result.append(number).toString();
        } catch (GeneralSecurityException e) {
            // Do not attach provider exceptions that might include key material.
            throw new IllegalStateException("设备不支持所选验证码算法");
        } finally {
            Arrays.fill(key, (byte) 0);
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    /** Full period at an exact boundary; otherwise seconds until the next code. */
    public static int remaining(Account account, long unixSeconds) {
        checkInputs(account, unixSeconds);
        return account.period - (int) (unixSeconds % account.period);
    }

    /** Decodes canonical Base32, accepting lowercase, ASCII spacing and optional RFC 4648 padding. */
    public static byte[] decodeBase32(String value) {
        String normalized = normalizeBase32(value);
        byte[] result = new byte[normalized.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            int digit = c >= 'A' && c <= 'Z' ? c - 'A' : c - '2' + 26;
            buffer = (buffer << 5) | digit;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                result[index++] = (byte) (buffer >>> bits);
                buffer &= (1 << bits) - 1;
            }
        }
        if (buffer != 0) {
            Arrays.fill(result, (byte) 0);
            throw invalidBase32();
        }
        return result;
    }

    static String normalizeBase32(String value) {
        if (value == null || value.isEmpty() || value.length() > 512) {
            throw invalidBase32();
        }
        StringBuilder data = new StringBuilder();
        int padding = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                continue;
            }
            if (c == '=') {
                padding++;
                continue;
            }
            if (padding != 0) {
                throw invalidBase32();
            }
            if (c >= 'a' && c <= 'z') {
                c = (char) (c - 'a' + 'A');
            }
            if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'))) {
                throw invalidBase32();
            }
            data.append(c);
        }
        int length = data.length();
        int remainder = length % 8;
        if (length == 0 || length > 205 || remainder == 1 || remainder == 3 || remainder == 6) {
            throw invalidBase32();
        }
        if (padding != 0 && (remainder == 0 || padding != 8 - remainder)) {
            throw invalidBase32();
        }
        return data.toString();
    }

    private static void checkInputs(Account account, long unixSeconds) {
        if (account == null || unixSeconds < 0) {
            throw new IllegalArgumentException("账号或系统时间无效");
        }
    }

    private static IllegalArgumentException invalidBase32() {
        return new IllegalArgumentException("密钥不是有效的 Base32 格式");
    }
}
