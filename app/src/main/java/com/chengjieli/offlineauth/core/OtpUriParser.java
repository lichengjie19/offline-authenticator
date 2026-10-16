package com.chengjieli.offlineauth.core;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/** Strict otpauth TOTP import; rejects HOTP, unknown parameters and ambiguous metadata. */
public final class OtpUriParser {
    private OtpUriParser() { }

    /** Export only through an explicit user action; the resulting URI contains the account secret. */
    public static String format(Account account) {
        if (account == null) throw new IllegalArgumentException("账号无效");
        if (account.issuer.indexOf(':') >= 0 || account.name.indexOf(':') >= 0) {
            throw new IllegalArgumentException("标准二维码不支持名称中的冒号，请先编辑服务或账号名称");
        }
        String label = account.issuer.isEmpty() ? encodeComponent(account.name)
                : encodeComponent(account.issuer) + ":" + encodeComponent(account.name);
        StringBuilder uri = new StringBuilder("otpauth://totp/").append(label)
                .append("?secret=").append(account.secret);
        if (!account.issuer.isEmpty()) uri.append("&issuer=").append(encodeComponent(account.issuer));
        return uri.append("&algorithm=").append(account.algorithm)
                .append("&digits=").append(account.digits)
                .append("&period=").append(account.period).toString();
    }

    private static String encodeComponent(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder encoded = new StringBuilder(bytes.length);
        final char[] hex = "0123456789ABCDEF".toCharArray();
        for (byte item : bytes) {
            int b = item & 0xff;
            if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
                    || (b >= '0' && b <= '9') || b == '-' || b == '.' || b == '_' || b == '~') {
                encoded.append((char) b);
            } else {
                encoded.append('%').append(hex[b >>> 4]).append(hex[b & 15]);
            }
        }
        return encoded.toString();
    }

    public static Account parse(String value) {
        if (value == null || value.length() > 4096) {
            throw invalidUri();
        }
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                throw invalidUri();
            }
        }
        final URI uri;
        try {
            uri = new URI(value.trim());
        } catch (URISyntaxException e) {
            // URI exception messages contain the complete input, including its secret.
            throw invalidUri();
        }
        if (!"otpauth".equalsIgnoreCase(uri.getScheme())
                || !"totp".equalsIgnoreCase(uri.getRawAuthority())
                || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("仅支持标准 otpauth://totp 验证器二维码");
        }
        String path = uri.getRawPath();
        if (path == null || !path.startsWith("/") || path.length() < 2
                || path.indexOf('/', 1) >= 0) {
            throw invalidUri();
        }
        String label = decodeComponent(path.substring(1));
        String labelIssuer = null;
        String name = label;
        int colon = label.indexOf(':');
        if (colon >= 0) {
            if (label.indexOf(':', colon + 1) >= 0) {
                throw new IllegalArgumentException("二维码中的账号标签格式无效");
            }
            labelIssuer = label.substring(0, colon).trim();
            name = label.substring(colon + 1).trim();
            if (labelIssuer.isEmpty()) {
                throw new IllegalArgumentException("二维码中的服务名称不能为空");
            }
        }
        Map<String, String> params = parseQuery(uri.getRawQuery());
        if (!params.containsKey("secret")) {
            throw new IllegalArgumentException("二维码缺少验证码密钥");
        }
        String issuer = params.containsKey("issuer") ? params.get("issuer").trim() : labelIssuer;
        if (params.containsKey("issuer") && issuer.isEmpty()) {
            throw new IllegalArgumentException("二维码中的服务名称不能为空");
        }
        if (issuer != null && issuer.indexOf(':') >= 0) {
            throw new IllegalArgumentException("二维码中的服务名称格式无效");
        }
        if (labelIssuer != null && params.containsKey("issuer") && !labelIssuer.equals(issuer)) {
            throw new IllegalArgumentException("二维码中的服务名称不一致");
        }
        String algorithm = params.containsKey("algorithm") ? params.get("algorithm") : "SHA1";
        int digits = params.containsKey("digits") ? positiveInteger(params.get("digits")) : 6;
        int period = params.containsKey("period") ? positiveInteger(params.get("period")) : 30;
        return Account.create(issuer == null ? "" : issuer, name, params.get("secret"),
                algorithm, digits, period);
    }

    private static Map<String, String> parseQuery(String query) {
        if (query == null || query.isEmpty()) {
            throw new IllegalArgumentException("二维码缺少验证码密钥");
        }
        Map<String, String> params = new HashMap<>();
        for (String pair : query.split("&", -1)) {
            int equals = pair.indexOf('=');
            if (equals <= 0) {
                throw invalidUri();
            }
            String key = decodeComponent(pair.substring(0, equals));
            if (!key.equals("secret") && !key.equals("issuer") && !key.equals("algorithm")
                    && !key.equals("digits") && !key.equals("period")) {
                throw new IllegalArgumentException("二维码包含不支持的参数");
            }
            if (params.containsKey(key)) {
                throw new IllegalArgumentException("二维码包含重复参数");
            }
            params.put(key, decodeComponent(pair.substring(equals + 1)));
        }
        return params;
    }

    private static int positiveInteger(String value) {
        if (value.isEmpty() || value.length() > 3) {
            throw new IllegalArgumentException("验证码位数或刷新周期格式无效");
        }
        int result = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("验证码位数或刷新周期格式无效");
            }
            result = result * 10 + c - '0';
        }
        return result;
    }

    private static String decodeComponent(String raw) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '%') {
                if (i + 2 >= raw.length()) {
                    throw invalidUri();
                }
                int high = Character.digit(raw.charAt(i + 1), 16);
                int low = Character.digit(raw.charAt(i + 2), 16);
                if (high < 0 || low < 0) {
                    throw invalidUri();
                }
                bytes.write((high << 4) | low);
                i += 2;
            } else if (c < 128) {
                // '+' is a literal plus in an URI component, not a form-encoded space.
                bytes.write(c);
            } else {
                String character;
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 >= raw.length() || !Character.isLowSurrogate(raw.charAt(i + 1))) {
                        throw invalidUri();
                    }
                    character = raw.substring(i, i + 2);
                    i++;
                } else {
                    if (Character.isLowSurrogate(c)) {
                        throw invalidUri();
                    }
                    character = String.valueOf(c);
                }
                byte[] encoded = character.getBytes(StandardCharsets.UTF_8);
                bytes.write(encoded, 0, encoded.length);
            }
        }
        try {
            String decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
            for (int i = 0; i < decoded.length(); i++) {
                if (Character.isISOControl(decoded.charAt(i))) {
                    throw invalidUri();
                }
            }
            return decoded;
        } catch (CharacterCodingException e) {
            throw invalidUri();
        }
    }

    private static IllegalArgumentException invalidUri() {
        return new IllegalArgumentException("二维码内容不是有效的 TOTP 绑定链接");
    }
}
