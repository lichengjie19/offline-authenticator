package com.chengjieli.offlineauth.core;

import static com.chengjieli.offlineauth.core.TotpTest.SHA1_SECRET;
import static com.chengjieli.offlineauth.core.TotpTest.expectInvalid;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.util.Arrays;
import org.junit.Test;

public class AccountTest {
    @Test public void normalizesInputsAndCreatesUniqueIds() {
        Account first = Account.create(" Example ", " alice ", SHA1_SECRET.toLowerCase(), " sha1 ", 6, 30);
        Account second = Account.create("Example", "alice", SHA1_SECRET, "SHA1", 6, 30);
        assertNotEquals(first.id, second.id);
        assertEquals("Example", first.issuer);
        assertEquals("alice", first.name);
        assertEquals(SHA1_SECRET, first.secret);
        assertEquals("SHA1", first.algorithm);
        assertEquals("Example · alice", first.displayTitle());
    }

    @Test public void acceptsAccountsWithoutIssuer() {
        Account account = Account.create(null, "alice", SHA1_SECRET, "SHA1", 6, 30);
        assertEquals("", account.issuer);
        assertEquals("alice", account.displayTitle());
    }

    @Test public void enforcesSecretLengthAndPreservesMaximumLength() {
        assertEquals(10, Totp.decodeBase32(Account.create("", "a", repeat('A', 16), "SHA1", 6, 30).secret).length);
        assertEquals(128, Totp.decodeBase32(Account.create("", "a", repeat('A', 205), "SHA512", 8, 30).secret).length);
        expectInvalid(() -> Account.create("", "a", repeat('A', 15), "SHA1", 6, 30));
        expectInvalid(() -> Account.create("", "a", repeat('A', 207), "SHA1", 6, 30));
        expectInvalid(() -> Account.create("", "a", repeat('A', 513), "SHA1", 6, 30));
    }

    @Test public void rejectsInvalidAlgorithmDigitsAndPeriod() {
        expectInvalid(() -> Account.create("", "a", SHA1_SECRET, "MD5", 6, 30));
        expectInvalid(() -> Account.create("", "a", SHA1_SECRET, null, 6, 30));
        expectInvalid(() -> Account.create("", "a", SHA1_SECRET, "SHA1", 7, 30));
        expectInvalid(() -> Account.create("", "a", SHA1_SECRET, "SHA1", 6, 14));
        expectInvalid(() -> Account.create("", "a", SHA1_SECRET, "SHA1", 6, 121));
        expectInvalid(() -> Account.create("", "a", SHA1_SECRET, "SHA1", 6, 0));
    }

    @Test public void constructorAlsoValidatesRestoredAccountsAndMetadata() {
        expectInvalid(() -> new Account("", "", "a", SHA1_SECRET, "SHA1", 6, 30));
        expectInvalid(() -> new Account(null, "", "a", SHA1_SECRET, "SHA1", 6, 30));
        expectInvalid(() -> new Account("id", "", " ", SHA1_SECRET, "SHA1", 6, 30));
        expectInvalid(() -> new Account("id", "evil\nissuer", "a", SHA1_SECRET, "SHA1", 6, 30));
        expectInvalid(() -> new Account("id", "", "a\u0000", SHA1_SECRET, "SHA1", 6, 30));
        expectInvalid(() -> new Account("id", "", "a\uD800", SHA1_SECRET, "SHA1", 6, 30));
        expectInvalid(() -> new Account("id", "", repeat('A', 257), SHA1_SECRET, "SHA1", 6, 30));
    }

    private static String repeat(char character, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, character);
        return new String(chars);
    }
}
