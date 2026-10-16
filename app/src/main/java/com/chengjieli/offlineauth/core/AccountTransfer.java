package com.chengjieli.offlineauth.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Non-destructive account merge: existing labels win, token duplicates are skipped. */
public final class AccountTransfer {
    private AccountTransfer() { }

    public static Result merge(List<Account> existing, List<Account> imported) {
        if (existing == null || imported == null || existing.size() > TransferCodec.MAX_ACCOUNTS
                || imported.size() > TransferCodec.MAX_ACCOUNTS) {
            throw new IllegalArgumentException("账号列表无效或超过 250 个账号限制");
        }
        List<Account> merged = new ArrayList<>(existing);
        Set<String> ids = new HashSet<>();
        Set<String> tokens = new HashSet<>();
        for (Account account : existing) {
            if (account == null || !ids.add(account.id)) {
                throw new IllegalArgumentException("现有账号列表无效，未执行导入");
            }
            tokens.add(token(account));
        }
        int skipped = 0;
        int added = 0;
        for (Account account : imported) {
            if (account == null) throw new IllegalArgumentException("备份中存在无效账号");
            if (!tokens.add(token(account))) {
                skipped++;
                continue;
            }
            if (merged.size() >= TransferCodec.MAX_ACCOUNTS) {
                throw new IllegalArgumentException("导入后将超过 250 个账号，未导入任何账号");
            }
            Account next = account;
            if (ids.contains(account.id)) {
                String newId;
                do { newId = UUID.randomUUID().toString(); } while (ids.contains(newId));
                next = new Account(newId, account.issuer, account.name, account.secret,
                        account.algorithm, account.digits, account.period);
            }
            ids.add(next.id);
            merged.add(next);
            added++;
        }
        return new Result(merged, added, skipped);
    }

    private static String token(Account account) {
        // Base32 and validated algorithm names never contain this separator.
        return account.secret + '\0' + account.algorithm + '\0' + account.digits + '\0' + account.period;
    }

    public static final class Result {
        public final List<Account> accounts;
        public final int added;
        public final int skipped;

        private Result(List<Account> accounts, int added, int skipped) {
            this.accounts = Collections.unmodifiableList(new ArrayList<>(accounts));
            this.added = added;
            this.skipped = skipped;
        }
    }
}
