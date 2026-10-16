package com.chengjieli.offlineauth.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import org.junit.Test;

public class TotpTest {
    static final String SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String SHA256_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    private static final String SHA512_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                    + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    @Test public void allRfc6238AppendixBTestVectors() {
        long[] times = {59L, 1_111_111_109L, 1_111_111_111L, 1_234_567_890L,
                2_000_000_000L, 20_000_000_000L};
        String[][] expected = {
                {"94287082", "46119246", "90693936"},
                {"07081804", "68084774", "25091201"},
                {"14050471", "67062674", "99943326"},
                {"89005924", "91819424", "93441116"},
                {"69279037", "90698825", "38618901"},
                {"65353130", "77737706", "47863826"}
        };
        Account[] accounts = {
                account(SHA1_SECRET, "SHA1", 8, 30),
                account(SHA256_SECRET, "SHA256", 8, 30),
                account(SHA512_SECRET, "SHA512", 8, 30)
        };
        for (int time = 0; time < times.length; time++) {
            for (int algorithm = 0; algorithm < accounts.length; algorithm++) {
                assertEquals("time=" + times[time] + ", algorithm=" + accounts[algorithm].algorithm,
                        expected[time][algorithm], Totp.generate(accounts[algorithm], times[time]));
            }
        }
    }

    @Test public void preservesLeadingZerosForSixDigits() {
        assertEquals("081804", Totp.generate(account(SHA1_SECRET, "SHA1", 6, 30), 1_111_111_109L));
    }

    @Test public void generatesCorrectCodeOnTimeWindowBoundaries() {
        Account account = account(SHA1_SECRET, "SHA1", 6, 30);
        assertEquals("755224", Totp.generate(account, 0));
        assertEquals("755224", Totp.generate(account, 29));
        assertEquals("287082", Totp.generate(account, 30));
        assertEquals("287082", Totp.generate(account, 59));
        assertEquals("359152", Totp.generate(account, 60));
    }

    @Test public void calculatesCountdownWithoutZeroAtBoundary() {
        Account account = account(SHA1_SECRET, "SHA1", 6, 30);
        assertEquals(30, Totp.remaining(account, 0));
        assertEquals(1, Totp.remaining(account, 29));
        assertEquals(30, Totp.remaining(account, 30));
        assertEquals(1, Totp.remaining(account, 59));
        assertEquals(10, Totp.remaining(account, 20_000_000_000L));
    }

    @Test public void honorsNonDefaultPeriods() {
        Account fast = account(SHA1_SECRET, "SHA1", 6, 15);
        Account slow = account(SHA1_SECRET, "SHA1", 6, 120);
        assertEquals("287082", Totp.generate(fast, 29));
        assertEquals(1, Totp.remaining(fast, 29));
        assertEquals("755224", Totp.generate(slow, 119));
        assertEquals("287082", Totp.generate(slow, 120));
        assertEquals(120, Totp.remaining(slow, 120));
    }

    @Test public void decodesRfc4648Base32VectorsWithOptionalPadding() {
        String[][] vectors = {
                {"f", "MY======"}, {"fo", "MZXQ===="}, {"foo", "MZXW6==="},
                {"foob", "MZXW6YQ="}, {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI======"}
        };
        for (String[] vector : vectors) {
            byte[] expected = vector[0].getBytes(StandardCharsets.US_ASCII);
            assertArrayEquals(expected, Totp.decodeBase32(vector[1]));
            assertArrayEquals(expected, Totp.decodeBase32(vector[1].replace("=", "")));
        }
        assertArrayEquals("foobar".getBytes(StandardCharsets.US_ASCII),
                Totp.decodeBase32(" mzxw 6ytb\noi\t======\r"));
    }

    @Test public void rejectsMalformedBase32AndNonZeroTrailingBits() {
        String[] invalid = {null, "", " ", "A", "AAA", "AAAAAA", "MZ", "MZ======",
                "MZXQ===", "MY=======", "MY=", "MY======A", "MZXW6YTB=", "M0", "M1",
                "M8", "M9", "M!", "ＭＹ", "MY-", "========", "MY\u0000"};
        for (String value : invalid) {
            expectInvalid(() -> Totp.decodeBase32(value));
        }
    }

    @Test public void rejectsInvalidTimesAndMissingAccount() {
        Account account = account(SHA1_SECRET, "SHA1", 6, 30);
        expectInvalid(() -> Totp.generate(account, -1));
        expectInvalid(() -> Totp.remaining(account, -1));
        expectInvalid(() -> Totp.generate(null, 0));
        expectInvalid(() -> Totp.remaining(null, 0));
    }

    static Account account(String secret, String algorithm, int digits, int period) {
        return new Account("test-id", "Example", "alice", secret, algorithm, digits, period);
    }

    static void expectInvalid(Runnable operation) {
        try {
            operation.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected validation failure.
        }
    }
}
