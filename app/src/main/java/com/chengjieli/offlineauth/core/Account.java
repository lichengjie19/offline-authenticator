package com.chengjieli.offlineauth.core;

import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;

/** Immutable, validated TOTP account. Never include the secret in logs or error messages. */
public final class Account {
    public final String id;
    public final String issuer;
    public final String name;
    public final String secret;
    public final String algorithm;
    public final int digits;
    public final int period;

    public Account(String id, String issuer, String name, String secret,
                   String algorithm, int digits, int period) {
        this.id = cleanText(id, "账号标识", 128, false);
        this.issuer = cleanText(issuer == null ? "" : issuer, "服务名称", 256, true);
        this.name = cleanText(name, "账号名称", 256, false);
        this.secret = Totp.normalizeBase32(secret);
        byte[] decodedSecret = Totp.decodeBase32(this.secret);
        int secretLength = decodedSecret.length;
        Arrays.fill(decodedSecret, (byte) 0);
        if (secretLength < 10 || secretLength > 128) {
            throw new IllegalArgumentException("密钥长度必须为 10 至 128 字节");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("请选择有效的验证码算法");
        }
        String normalizedAlgorithm = algorithm.trim().toUpperCase(Locale.ROOT);
        if (!normalizedAlgorithm.equals("SHA1") && !normalizedAlgorithm.equals("SHA256")
                && !normalizedAlgorithm.equals("SHA512")) {
            throw new IllegalArgumentException("仅支持 SHA1、SHA256 和 SHA512 算法");
        }
        if (digits != 6 && digits != 8) {
            throw new IllegalArgumentException("验证码仅支持 6 位或 8 位");
        }
        if (period < 15 || period > 120) {
            throw new IllegalArgumentException("刷新周期必须为 15 至 120 秒");
        }
        this.algorithm = normalizedAlgorithm;
        this.digits = digits;
        this.period = period;
    }

    public static Account create(String issuer, String name, String secret,
                                 String algorithm, int digits, int period) {
        return new Account(UUID.randomUUID().toString(), issuer, name, secret,
                algorithm, digits, period);
    }

    public String displayTitle() {
        return issuer.isEmpty() ? name : issuer + " · " + name;
    }

    private static String cleanText(String value, String field, int maxLength, boolean emptyAllowed) {
        if (value == null) {
            throw new IllegalArgumentException(field + "不能为空");
        }
        // Check the original string, before trim(), so encoded control characters are rejected.
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c)) {
                throw new IllegalArgumentException(field + "包含无效字符");
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(++i))) {
                    throw new IllegalArgumentException(field + "包含无效字符");
                }
            } else if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException(field + "包含无效字符");
            }
        }
        String result = value.trim();
        if ((!emptyAllowed && result.isEmpty()) || result.length() > maxLength) {
            throw new IllegalArgumentException(field + "为空或过长");
        }
        return result;
    }
}
