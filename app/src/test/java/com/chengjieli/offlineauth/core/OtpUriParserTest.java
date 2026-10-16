package com.chengjieli.offlineauth.core;

import static com.chengjieli.offlineauth.core.TotpTest.SHA1_SECRET;
import static com.chengjieli.offlineauth.core.TotpTest.expectInvalid;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.junit.Test;

public class OtpUriParserTest {
    private static final String QUERY = "?secret=" + SHA1_SECRET;

    @Test public void formattedUriRoundTripsUnicodeAndReservedCharacters() {
        Account original = Account.create("测试 + 服务🔑", "alice+qa%/team&x=y@example.com", SHA1_SECRET, "SHA512", 8, 60);
        String uri = OtpUriParser.format(original);
        assertFalse(uri.contains(" "));
        assertFalse(uri.contains("测试"));
        Account restored = OtpUriParser.parse(uri);
        assertEquals(original.issuer, restored.issuer);
        assertEquals(original.name, restored.name);
        assertEquals(original.secret, restored.secret);
        assertEquals(original.algorithm, restored.algorithm);
        assertEquals(original.digits, restored.digits);
        assertEquals(original.period, restored.period);
    }

    @Test public void formattedUriWithoutIssuerRoundTripsAndUsesExplicitParameters() {
        Account original = Account.create("", "alice@example.com", SHA1_SECRET, "SHA1", 6, 30);
        String uri = OtpUriParser.format(original);
        assertFalse(uri.contains("&issuer="));
        assertEquals("", OtpUriParser.parse(uri).issuer);
        assertEquals(original.name, OtpUriParser.parse(uri).name);
    }

    @Test public void formatterRejectsUnrepresentableColonLabelsAndNullAccount() {
        expectInvalid(() -> OtpUriParser.format(null));
        expectInvalid(() -> OtpUriParser.format(Account.create("A:B", "alice", SHA1_SECRET, "SHA1", 6, 30)));
        expectInvalid(() -> OtpUriParser.format(Account.create("A", "alice:qa", SHA1_SECRET, "SHA1", 6, 30)));
    }

    @Test public void parsesCommonGithubStyleUriWithDefaults() {
        Account account = OtpUriParser.parse("otpauth://totp/GitHub:alice" + QUERY + "&issuer=GitHub");
        assertEquals("GitHub", account.issuer);
        assertEquals("alice", account.name);
        assertEquals(SHA1_SECRET, account.secret);
        assertEquals("SHA1", account.algorithm);
        assertEquals(6, account.digits);
        assertEquals(30, account.period);
    }

    @Test public void parsesExplicitSupportedParameters() {
        Account account = OtpUriParser.parse("otpauth://totp/alice" + QUERY
                + "&issuer=Example&algorithm=SHA512&digits=8&period=60");
        assertEquals("Example", account.issuer);
        assertEquals("SHA512", account.algorithm);
        assertEquals(8, account.digits);
        assertEquals(60, account.period);
    }

    @Test public void supportsIssuerOnlyInLabelOrOnlyInQueryOrNeither() {
        assertEquals("Example", OtpUriParser.parse("otpauth://totp/Example:alice" + QUERY).issuer);
        assertEquals("Example", OtpUriParser.parse("otpauth://totp/alice" + QUERY + "&issuer=Example").issuer);
        assertEquals("", OtpUriParser.parse("otpauth://totp/alice" + QUERY).issuer);
    }

    @Test public void decodesUnicodePercentEscapesAndPreservesPlus() {
        Account escaped = OtpUriParser.parse("otpauth://totp/%E6%B5%8B%E8%AF%95%3A%E5%BC%A0%E4%B8%89%2Bdev%40example.com"
                + QUERY + "&issuer=%E6%B5%8B%E8%AF%95");
        assertEquals("测试", escaped.issuer);
        assertEquals("张三+dev@example.com", escaped.name);
        Account unicode = OtpUriParser.parse("otpauth://totp/测试:张三+dev@example.com" + QUERY + "&issuer=测试");
        assertEquals(escaped.issuer, unicode.issuer);
        assertEquals(escaped.name, unicode.name);
        Account plus = OtpUriParser.parse("otpauth://totp/A+B:alice%25dev" + QUERY + "&issuer=A+B");
        assertEquals("A+B", plus.issuer);
        assertEquals("alice%dev", plus.name);
    }

    @Test public void rejectsUnsupportedUriStructures() {
        String[] invalid = {null, "", "https://totp/alice" + QUERY, "otpauth://hotp/alice" + QUERY,
                "otpauth://user@totp/alice" + QUERY, "otpauth://totp:443/alice" + QUERY,
                "otpauth:totp/alice" + QUERY, "otpauth://totp/" + QUERY,
                "otpauth://totp/a/b" + QUERY, "otpauth://totp/a" + QUERY + "#fragment",
                "otpauth://totp/%ZZ" + QUERY, "otpauth://totp/%C0%AF" + QUERY,
                "otpauth://totp/%E2%82" + QUERY, "otpauth://totp/%00alice" + QUERY,
                "otpauth://totp/%0AExample:alice" + QUERY,
                "otpauth://totp/alice" + QUERY + "\u0000"};
        for (String uri : invalid) {
            expectInvalid(() -> OtpUriParser.parse(uri));
        }
    }

    @Test public void rejectsMissingEmptyRepeatedUnknownOrInvalidParameters() {
        String base = "otpauth://totp/alice";
        String[] endings = {"", "?", "?issuer=Example", "?secret=", "?secret=A",
                QUERY + "&secret=" + SHA1_SECRET, QUERY + "&%73ecret=" + SHA1_SECRET,
                QUERY + "&issuer=A&issuer=A", QUERY + "&counter=0", QUERY + "&unknown=1",
                QUERY + "&", QUERY + "&&digits=6", QUERY + "&digits", QUERY + "&=a",
                QUERY + "&algorithm=MD5", QUERY + "&algorithm=", QUERY + "&digits=7",
                QUERY + "&digits=-6", QUERY + "&digits=+6", QUERY + "&digits=6.0",
                QUERY + "&digits=", QUERY + "&period=14", QUERY + "&period=121",
                QUERY + "&period=99999999999999", QUERY + "&issuer=", QUERY + "&issuer=%0AA",
                QUERY + "&issuer=A%3AB"};
        for (String ending : endings) {
            expectInvalid(() -> OtpUriParser.parse(base + ending));
        }
    }

    @Test public void rejectsAmbiguousIssuerAndInvalidLabels() {
        String[] invalid = {"otpauth://totp/A:alice" + QUERY + "&issuer=B",
                "otpauth://totp/:alice" + QUERY, "otpauth://totp/A:" + QUERY,
                "otpauth://totp/A:alice:extra" + QUERY,
                "otpauth://totp/A:alice" + QUERY + "&issuer=a",
                "otpauth://totp/%20" + QUERY};
        for (String uri : invalid) {
            expectInvalid(() -> OtpUriParser.parse(uri));
        }
    }

    @Test public void errorsDoNotEchoUriOrSecretOrCarryUnsafeCause() {
        String[] invalid = {"otpauth://totp/%ZZ" + QUERY,
                "otpauth://totp/alice" + QUERY + "&secret=" + SHA1_SECRET,
                "otpauth://totp/alice?secret=" + SHA1_SECRET + "!"};
        for (String uri : invalid) {
            try {
                OtpUriParser.parse(uri);
                fail("Expected invalid URI");
            } catch (IllegalArgumentException expected) {
                assertFalse(expected.getMessage().contains(SHA1_SECRET));
                assertFalse(expected.getMessage().contains("otpauth://"));
                assertNull(expected.getCause());
            }
        }
    }
}
