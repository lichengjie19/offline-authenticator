package com.chengjieli.offlineauth.core;

import static com.chengjieli.offlineauth.core.TotpTest.SHA1_SECRET;
import static com.chengjieli.offlineauth.core.TotpTest.expectInvalid;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

public class AccountTransferTest {
    @Test public void skipsTokenDuplicatesAndPreservesExistingLabelsAndIds() {
        Account existing = account("existing", "Current label", SHA1_SECRET, "SHA1", 6, 30);
        Account duplicate = account("different-id", "Imported label", SHA1_SECRET.toLowerCase(), "SHA1", 6, 30);
        AccountTransfer.Result result = AccountTransfer.merge(Collections.singletonList(existing),
                Arrays.asList(duplicate, duplicate));
        assertEquals(0, result.added);
        assertEquals(2, result.skipped);
        assertEquals(1, result.accounts.size());
        assertSame(existing, result.accounts.get(0));
    }

    @Test public void tokenIdentityIncludesAlgorithmDigitsAndPeriod() {
        Account existing = account("a", "Example", SHA1_SECRET, "SHA1", 6, 30);
        List<Account> imported = Arrays.asList(
                account("b", "Example", SHA1_SECRET, "SHA256", 6, 30),
                account("c", "Example", SHA1_SECRET, "SHA1", 8, 30),
                account("d", "Example", SHA1_SECRET, "SHA1", 6, 60));
        AccountTransfer.Result result = AccountTransfer.merge(Collections.singletonList(existing), imported);
        assertEquals(3, result.added);
        assertEquals(0, result.skipped);
        assertEquals(4, result.accounts.size());
    }

    @Test public void collidingImportedIdsAreRegeneratedWithoutLosingAccounts() {
        Account existing = account("same-id", "Original", secretFor(0), "SHA1", 6, 30);
        Account first = account("same-id", "Imported one", secretFor(1), "SHA1", 6, 30);
        Account second = account("same-id", "Imported two", secretFor(2), "SHA1", 6, 30);
        AccountTransfer.Result result = AccountTransfer.merge(Collections.singletonList(existing), Arrays.asList(first, second));
        assertEquals(2, result.added);
        assertEquals(0, result.skipped);
        assertEquals(3, result.accounts.size());
        assertSame(existing, result.accounts.get(0));
        Set<String> ids = new HashSet<>();
        for (Account account : result.accounts) assertTrue(ids.add(account.id));
        assertNotEquals(first.id, result.accounts.get(1).id);
        assertEquals(first.secret, result.accounts.get(1).secret);
        assertEquals(second.issuer, result.accounts.get(2).issuer);
        assertEquals("same-id", first.id);
        assertEquals("same-id", second.id);
    }

    @Test public void repeatedImportedTokensAreSkippedAfterTheFirst() {
        Account first = account("one", "First", SHA1_SECRET, "SHA1", 6, 30);
        Account second = account("two", "Second", SHA1_SECRET, "SHA1", 6, 30);
        AccountTransfer.Result result = AccountTransfer.merge(Collections.emptyList(), Arrays.asList(first, second));
        assertEquals(1, result.added);
        assertEquals(1, result.skipped);
        assertSame(first, result.accounts.get(0));
    }

    @Test public void exceedingAccountLimitRejectsWholeMergeWithoutChangingInputs() {
        List<Account> existing = new ArrayList<>();
        for (int i = 0; i < 249; i++) existing.add(account("id-" + i, "Example", secretFor(i), "SHA1", 6, 30));
        List<Account> imported = Arrays.asList(
                account("new-1", "Example", secretFor(249), "SHA1", 6, 30),
                account("new-2", "Example", secretFor(250), "SHA1", 6, 30));
        expectInvalid(() -> AccountTransfer.merge(existing, imported));
        assertEquals(249, existing.size());
        assertEquals(2, imported.size());
        AccountTransfer.Result full = AccountTransfer.merge(existing, Collections.singletonList(imported.get(0)));
        assertEquals(250, full.accounts.size());
        AccountTransfer.Result duplicatesAtLimit = AccountTransfer.merge(full.accounts, Collections.singletonList(imported.get(0)));
        assertEquals(0, duplicatesAtLimit.added);
        assertEquals(1, duplicatesAtLimit.skipped);
    }

    @Test public void resultIsIndependentAndUnmodifiable() {
        List<Account> existing = new ArrayList<>();
        existing.add(account("one", "Example", SHA1_SECRET, "SHA1", 6, 30));
        AccountTransfer.Result result = AccountTransfer.merge(existing, Collections.emptyList());
        existing.clear();
        assertEquals(1, result.accounts.size());
        try {
            result.accounts.clear();
            fail("Result must be unmodifiable");
        } catch (UnsupportedOperationException expected) {
            // Immutable merge preview.
        }
    }

    @Test public void rejectsNullListsNullAccountsAndInvalidExistingIds() {
        Account one = account("same", "Example", secretFor(1), "SHA1", 6, 30);
        Account two = account("same", "Example", secretFor(2), "SHA1", 6, 30);
        expectInvalid(() -> AccountTransfer.merge(null, Collections.emptyList()));
        expectInvalid(() -> AccountTransfer.merge(Collections.emptyList(), null));
        expectInvalid(() -> AccountTransfer.merge(Collections.singletonList(null), Collections.emptyList()));
        expectInvalid(() -> AccountTransfer.merge(Collections.emptyList(), Collections.singletonList(null)));
        expectInvalid(() -> AccountTransfer.merge(Arrays.asList(one, two), Collections.emptyList()));
    }

    private static Account account(String id, String label, String secret, String algorithm, int digits, int period) {
        return new Account(id, label, "test@example.com", secret, algorithm, digits, period);
    }

    private static String secretFor(int counter) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        return "" + alphabet.charAt((counter >>> 5) & 31) + alphabet.charAt(counter & 31) + SHA1_SECRET.substring(2);
    }
}
