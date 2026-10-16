package com.chengjieli.offlineauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.BySelector;
import androidx.test.uiautomator.Configurator;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;

import com.chengjieli.offlineauth.core.Account;
import com.chengjieli.offlineauth.core.Totp;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/** End-to-end UI flow using only public RFC test secrets in the isolated debug package. */
@RunWith(AndroidJUnit4.class)
@LargeTest
public final class MainFlowTest {
    private static final String DEBUG_PACKAGE = "com.chengjieli.offlineauth.debug";
    private static final long TIMEOUT = 5_000;
    private static final String FIRST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String SECOND_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    private static final Pattern CODE = Pattern.compile("[0-9]{3} [0-9]{3}");
    private static final Pattern COUNTDOWN = Pattern.compile("6 位动态码 · ([1-9]|[12][0-9]|30) 秒后更新");

    private Instrumentation instrumentation;
    private Context target;
    private UiDevice device;
    private VaultStore vault;
    private MainActivity activity;
    private long previousIdleTimeout;
    private boolean configured;

    @Before public void setUp() throws Exception {
        instrumentation = InstrumentationRegistry.getInstrumentation();
        target = instrumentation.getTargetContext();
        // These guards must run before touching a vault. Never target the installed release app.
        assertEquals("UI tests may only reset the isolated debug package", DEBUG_PACKAGE, target.getPackageName());
        assertTrue("UI tests require a debug build", BuildConfig.DEBUG);
        device = UiDevice.getInstance(instrumentation);
        previousIdleTimeout = Configurator.getInstance().getWaitForIdleTimeout();
        Configurator.getInstance().setWaitForIdleTimeout(200);
        configured = true;
        device.wakeUp();
        vault = new VaultStore(target);
        vault.save(Collections.emptyList());
        launch();
    }

    @After public void tearDown() throws Exception {
        try {
            finishActivity();
            if (vault != null && target != null && DEBUG_PACKAGE.equals(target.getPackageName())
                    && BuildConfig.DEBUG) {
                // Keep the process alive; pm clear/force-stop would kill the instrumentation runner.
                vault.save(Collections.emptyList());
            }
        } finally {
            if (configured) {
                Configurator.getInstance().setWaitForIdleTimeout(previousIdleTimeout);
            }
        }
    }

    @Test public void manualAccountsSearchRenameDeleteAndRelaunchPersistCorrectly() throws Exception {
        waitText("添加你的第一个账号");
        waitText("我的账号  /  0");
        assertEquals(0, vault.load().size());

        addManually("GitHub", "test@example.com", FIRST_SECRET);
        waitText("我的账号  /  1");
        waitText("GitHub");
        waitText("test@example.com");
        Account original = accountNamed("test@example.com");
        assertEquals(FIRST_SECRET, original.secret);

        addManually("Example", "qa@example.com", SECOND_SECRET);
        waitText("我的账号  /  2");
        assertEquals(2, vault.load().size());

        // Filter to one card so assertions stay reliable on small displays.
        search("GitHub");
        waitText("test@example.com");
        assertFalse(device.hasObject(By.text("qa@example.com")));
        assertLiveCodeAndCountdown(original);

        search("no-such-test-account");
        waitText("没有匹配的账号");
        waitText("我的账号  /  2");
        search("QA@EXAMPLE.COM");
        waitText("qa@example.com");
        assertFalse(device.hasObject(By.text("test@example.com")));
        search("");

        // Duplicate rejection must leave the dialog open and preserve the encrypted vault.
        openManual("Duplicate", "duplicate@example.com", FIRST_SECRET);
        clickText("保存账号");
        instrumentation.waitForIdleSync();
        waitText("手动添加账号");
        assertEquals("The same TOTP secret and parameters must not create another account", 2, vault.load().size());
        assertFalse(containsName(vault.load(), "duplicate@example.com"));
        clickText("取消");
        waitGone(By.text("手动添加账号"));

        search("GitHub");
        manage("GitHub", "test@example.com");
        clickText("编辑名称");
        field("服务名称").setText("GitHub Work");
        field("账号").setText("renamed@example.com");
        clickText("保存");
        waitText("GitHub Work");
        waitText("renamed@example.com");
        Account renamed = accountNamed("renamed@example.com");
        assertEquals(original.id, renamed.id);
        assertEquals(original.secret, renamed.secret);
        assertEquals(original.algorithm, renamed.algorithm);
        assertEquals(original.digits, renamed.digits);
        assertEquals(original.period, renamed.period);

        // Cancelling a destructive action must leave both records unchanged.
        manage("GitHub Work", "renamed@example.com");
        clickText("删除账号");
        waitText("删除这个账号？");
        clickText("取消");
        waitGone(By.text("删除这个账号？"));
        waitText("renamed@example.com");
        assertEquals(2, vault.load().size());
        assertEquals(original.id, accountNamed("renamed@example.com").id);

        search("qa@example.com");
        manage("Example", "qa@example.com");
        clickText("删除账号");
        waitText("删除这个账号？");
        clickText("确认删除");
        waitGone(By.text("删除这个账号？"));
        waitText("我的账号  /  1");
        waitText("没有匹配的账号");
        assertEquals(1, vault.load().size());
        assertFalse(containsName(vault.load(), "qa@example.com"));
        search("");
        waitText("GitHub Work");

        // Destroy and construct a fresh Activity to prove the list is restored from storage.
        finishActivity();
        launch();
        waitText("我的账号  /  1");
        waitText("GitHub Work");
        waitText("renamed@example.com");
        assertFalse(device.hasObject(By.text("qa@example.com")));
        Account restored = accountNamed("renamed@example.com");
        assertEquals(original.id, restored.id);
        assertEquals(FIRST_SECRET, restored.secret);
        assertLiveCodeAndCountdown(restored);
    }

    private void launch() {
        Intent intent = new Intent(target, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        activity = (MainActivity) instrumentation.startActivitySync(intent);
        waitText("离线验证器");
    }

    private void finishActivity() {
        if (activity != null && instrumentation != null) {
            MainActivity closing = activity;
            instrumentation.runOnMainSync(() -> {
                if (!closing.isFinishing()) closing.finish();
            });
            instrumentation.waitForIdleSync();
            activity = null;
        }
    }

    private void openManual(String issuer, String name, String secret) {
        clickText("手动添加");
        waitText("手动添加账号");
        field("服务名称（如 GitHub）").setText(issuer);
        field("账号名称或邮箱").setText(name);
        field("设置密钥（Base32）").setText(secret);
    }

    private void addManually(String issuer, String name, String secret) {
        openManual(issuer, name, secret);
        clickText("保存账号");
        waitGone(By.text("手动添加账号"));
    }

    private void search(String query) {
        field("搜索服务或账号").setText(query);
        instrumentation.waitForIdleSync();
    }

    private void manage(String issuer, String name) {
        waitObject(By.desc("管理 " + issuer + " " + name)).click();
        waitText("编辑名称");
    }

    private UiObject2 field(String description) {
        return waitObject(By.desc(description).clazz("android.widget.EditText"));
    }

    private void clickText(String text) {
        waitText(text).click();
    }

    private UiObject2 waitText(String text) {
        return waitObject(By.text(text));
    }

    private UiObject2 waitObject(BySelector selector) {
        UiObject2 object = device.wait(Until.findObject(selector), TIMEOUT);
        assertNotNull("Expected UI element: " + selector, object);
        return object;
    }

    private void waitGone(BySelector selector) {
        assertTrue("Unexpected lingering UI element: " + selector,
                device.wait(Until.gone(selector), TIMEOUT));
    }

    private void assertLiveCodeAndCountdown(Account account) {
        String displayedCode = waitObject(By.text(CODE)).getText().replace(" ", "");
        long now = System.currentTimeMillis() / 1000;
        // A UI frame may straddle a one-second tick or the TOTP window boundary.
        boolean matches = displayedCode.equals(Totp.generate(account, now))
                || displayedCode.equals(Totp.generate(account, now - 1))
                || displayedCode.equals(Totp.generate(account, now + 1));
        assertTrue("The displayed code must match the test account's current TOTP", matches);
        String firstCountdown = waitObject(By.text(COUNTDOWN)).getText();
        awaitCondition(() -> {
            UiObject2 countdown = device.findObject(By.text(COUNTDOWN));
            return countdown != null && !firstCountdown.equals(countdown.getText());
        }, 3_500, "The visible countdown must continue updating");
    }

    private void awaitCondition(BooleanSupplier condition, long timeout, String message) {
        long end = SystemClock.uptimeMillis() + timeout;
        while (SystemClock.uptimeMillis() < end) {
            if (condition.getAsBoolean()) return;
            SystemClock.sleep(100);
        }
        assertTrue(message, condition.getAsBoolean());
    }

    private Account accountNamed(String name) throws Exception {
        for (Account account : vault.load()) {
            if (account.name.equals(name)) return account;
        }
        throw new AssertionError("Expected synthetic account was not saved: " + name);
    }

    private static boolean containsName(List<Account> accounts, String name) {
        for (Account account : accounts) {
            if (account.name.equals(name)) return true;
        }
        return false;
    }
}
