package com.chengjieli.offlineauth;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.SystemClock;
import android.view.WindowManager;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.Configurator;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;

import com.chengjieli.offlineauth.core.Account;
import com.chengjieli.offlineauth.core.OtpUriParser;
import com.chengjieli.offlineauth.core.TransferCodec;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/** Transfer end-to-end tests use public synthetic RFC secrets in the separate debug app only. */
@RunWith(AndroidJUnit4.class)
public final class TransferFlowTest {
    private static final String PASSWORD = "test-only-backup-password";
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private Instrumentation instrumentation;
    private Context context;
    private UiDevice device;
    private VaultStore vault;
    private List<Account> original;
    private TransferActivity activity;
    private final List<File> files = new ArrayList<>();
    private final List<Instrumentation.ActivityMonitor> monitors = new ArrayList<>();
    private long idleTimeout;

    @Before public void prepare() throws Exception {
        instrumentation = InstrumentationRegistry.getInstrumentation();
        context = instrumentation.getTargetContext();
        assertEquals("Never mutate the release vault", "com.chengjieli.offlineauth.debug", context.getPackageName());
        assertTrue(BuildConfig.DEBUG);
        device = UiDevice.getInstance(instrumentation); device.wakeUp();
        idleTimeout = Configurator.getInstance().getWaitForIdleTimeout();
        Configurator.getInstance().setWaitForIdleTimeout(150);
        vault = new VaultStore(context); original = vault.load(); vault.save(samples());
    }

    @After public void cleanup() throws Exception {
        for (Instrumentation.ActivityMonitor monitor : monitors) instrumentation.removeMonitor(monitor);
        if (activity != null) instrumentation.runOnMainSync(() -> activity.finish());
        instrumentation.waitForIdleSync();
        if (original != null) vault.save(original);
        for (File file : files) file.delete();
        Configurator.getInstance().setWaitForIdleTimeout(idleTimeout);
    }

    @Test public void encryptedExportAndPreviewedImportPreserveExistingAccounts() throws Exception {
        launch(null); File file = file();
        picker(Intent.ACTION_CREATE_DOCUMENT, "application/octet-stream", file, Activity.RESULT_OK);
        click("导出全部账号"); field("备份密码").setText(PASSWORD);
        field("再次输入备份密码").setText(PASSWORD); click("加密并选择位置");
        waitContains("加密备份已保存");
        byte[] encrypted = Files.readAllBytes(file.toPath());
        List<Account> exported = TransferCodec.decrypt(encrypted, PASSWORD.toCharArray());
        assertEquals(2, exported.size());
        assertFalse(new String(encrypted, java.nio.charset.StandardCharsets.ISO_8859_1).contains(SECRET));

        Account first = samples().get(0);
        Account retained = new Account(first.id, "Existing local title", "local@example.test",
                first.secret, first.algorithm, first.digits, first.period);
        Account extra = Account.create("Added later", "later@example.test", SECRET, "SHA512", 6, 30);
        vault.save(Arrays.asList(retained, extra));
        picker(Intent.ACTION_OPEN_DOCUMENT, "*/*", file, Activity.RESULT_OK);
        click("导入加密备份"); field("备份解密密码").setText(PASSWORD); click("解密并预览");
        waitText("确认导入账号"); waitContains("新增 1 个账号"); waitContains("跳过重复 1 个账号");
        assertEquals("Preview must never persist", 2, vault.load().size());
        click("确认导入"); waitContains("导入完成：新增 1 个");
        List<Account> merged = vault.load(); assertEquals(3, merged.size());
        assertEquals("Existing local title", merged.get(0).issuer);
        assertEquals("local@example.test", merged.get(0).name);
        assertEquals(extra.id, merged.get(1).id);
    }

    @Test public void wrongPasswordAndCancelledPreviewLeaveVaultUntouched() throws Exception {
        launch(null); File file = file();
        Files.write(file.toPath(), TransferCodec.encrypt(samples(), PASSWORD.toCharArray()));
        byte[] originalBytes = rawVault();
        picker(Intent.ACTION_OPEN_DOCUMENT, "*/*", file, Activity.RESULT_OK);
        click("导入加密备份"); field("备份解密密码").setText("wrong-password"); click("解密并预览");
        waitContains("无法导入：密码错误"); assertArrayEquals(originalBytes, rawVault());

        picker(Intent.ACTION_OPEN_DOCUMENT, "*/*", file, Activity.RESULT_OK);
        click("导入加密备份"); field("备份解密密码").setText(PASSWORD); click("解密并预览");
        waitText("确认导入账号"); click("取消"); waitContains("已取消导入");
        assertArrayEquals(originalBytes, rawVault());
    }

    @Test public void cancellingSystemPickerDoesNotChangeVault() throws Exception {
        launch(null); byte[] before = rawVault();
        picker(Intent.ACTION_OPEN_DOCUMENT, "*/*", null, Activity.RESULT_CANCELED);
        click("导入加密备份"); waitContains("已取消转移"); assertArrayEquals(before, rawVault());
    }

    @Test public void backgroundingDuringEncryptionCancelsPickerAndRestoresButtons() throws Exception {
        launch(null); File file = file(); byte[] before = rawVault();
        picker(Intent.ACTION_CREATE_DOCUMENT, "application/octet-stream", file, Activity.RESULT_OK);
        Instrumentation.ActivityMonitor pickerMonitor = monitors.get(0);
        ExecutorService executor = (ExecutorService) member("worker");
        CountDownLatch queued = new CountDownLatch(1), release = new CountDownLatch(1);
        // Hold the worker until the Activity is paused, making encryption-result timing
        // deterministic instead of racing the emulator's PBKDF2 implementation.
        executor.execute(() -> {
            queued.countDown();
            try { release.await(); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        });
        try {
            assertTrue("Worker gate must start", queued.await(5, TimeUnit.SECONDS));
            click("导出全部账号"); field("备份密码").setText(PASSWORD);
            field("再次输入备份密码").setText(PASSWORD); click("加密并选择位置");
            waitContains("正在加密备份");
            device.pressHome();
            waitBooleanMember("resumed", false, 5000);
        } finally { release.countDown(); }

        waitBooleanMember("busy", false, 20000);
        assertEquals("An encryption completion must not launch the picker in background", 0, pickerMonitor.getHits());
        assertNull("Cancelled ciphertext must not stay pending", member("pendingExport"));
        assertEquals("No backup file should be written", 0L, file.length());
        assertArrayEquals(before, rawVault());
        context.startActivity(new Intent(context, TransferActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT));
        waitContains("导出已取消，请回到页面重新导出");
        assertTrue("Export must be available again after cancellation", waitText("导出全部账号").isEnabled());
        for (Object control : (List<?>) member("controls")) {
            assertTrue("All transfer actions must be enabled", ((android.view.View) control).isEnabled());
        }
    }

    @Test public void accountQrMatchesStoredParametersAndClosesInBackground() throws Exception {
        Account expected = samples().get(0); launch(expected.id);
        waitText("转移此账号");
        assertNotEquals(0, activity.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE);
        Bitmap bitmap = (Bitmap) member("qrBitmap"); assertNotNull(bitmap);
        AlertDialog dialog = (AlertDialog) member("qrDialog"); assertNotNull(dialog);
        assertNotEquals(0, dialog.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE);
        int[] pixels = new int[bitmap.getWidth() * bitmap.getHeight()];
        bitmap.getPixels(pixels, 0, bitmap.getWidth(), 0, 0, bitmap.getWidth(), bitmap.getHeight());
        Account decoded = OtpUriParser.parse(QrDecoder.decodeArgb(pixels, bitmap.getWidth(), bitmap.getHeight()));
        Arrays.fill(pixels, 0);
        assertEquals(expected.secret, decoded.secret); assertEquals(expected.algorithm, decoded.algorithm);
        assertEquals(expected.name, decoded.name); assertEquals(expected.period, decoded.period);
        device.pressHome();
        long deadline = SystemClock.uptimeMillis() + 5000;
        while (member("qrBitmap") != null && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(30);
        assertNull(member("qrBitmap")); assertNull(member("qrDialog")); assertTrue(bitmap.isRecycled());
        assertEquals(2, vault.load().size());
    }

    @Test public void rotationCancelsPendingImportWithoutSavingSecrets() throws Exception {
        launch(null); File file = file();
        Files.write(file.toPath(), TransferCodec.encrypt(samples(), PASSWORD.toCharArray()));
        picker(Intent.ACTION_OPEN_DOCUMENT, "*/*", file, Activity.RESULT_OK);
        click("导入加密备份"); field("备份解密密码").setText(PASSWORD);
        byte[] before = rawVault();
        Instrumentation.ActivityMonitor replacement = instrumentation.addMonitor(TransferActivity.class.getName(), null, false);
        monitors.add(replacement);
        instrumentation.runOnMainSync(() -> activity.recreate());
        Activity recreated = instrumentation.waitForMonitorWithTimeout(replacement, 7000);
        assertNotNull(recreated); activity = (TransferActivity) recreated;
        waitContains("尚未确认的转移已取消");
        assertFalse(device.hasObject(By.desc("备份解密密码")));
        assertArrayEquals(before, rawVault());
    }

    private static List<Account> samples() {
        return Arrays.asList(new Account("transfer-first", "Synthetic GitHub", "first@example.test", SECRET, "SHA1", 6, 30),
                new Account("transfer-second", "Synthetic Work", "second@example.test", SECRET, "SHA256", 8, 60));
    }
    private void launch(String accountId) {
        Intent intent = new Intent(context, TransferActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        if (accountId != null) intent.putExtra("account_id", accountId);
        activity = (TransferActivity) instrumentation.startActivitySync(intent);
        if (accountId == null) {
            waitText("备份与转移");
            waitContains("本机共有 2 个账号");
        } else {
            // Direct account transfer opens a modal immediately after the async load;
            // accessibility may already exclude the covered Activity title.
            waitText("转移此账号");
        }
    }
    private File file() throws Exception { File file = File.createTempFile("transfer-test-", ".oab", context.getCacheDir()); files.add(file); return file; }
    private byte[] rawVault() throws Exception { return Files.readAllBytes(new File(context.getNoBackupFilesDir(), "vault.bin").toPath()); }
    private Object member(String name) throws Exception {
        Field field = TransferActivity.class.getDeclaredField(name); field.setAccessible(true);
        AtomicReference<Object> result = new AtomicReference<>();
        instrumentation.runOnMainSync(() -> { try { result.set(field.get(activity)); } catch (Exception failure) { throw new AssertionError(failure); } });
        return result.get();
    }
    private void waitBooleanMember(String name, boolean expected, long timeout) throws Exception {
        long deadline = SystemClock.uptimeMillis() + timeout;
        while (!Boolean.valueOf(expected).equals(member(name)) && SystemClock.uptimeMillis() < deadline) {
            SystemClock.sleep(40);
        }
        assertEquals("Unexpected Activity state: " + name, Boolean.valueOf(expected), member(name));
    }
    private void picker(String action, String type, File file, int result) throws Exception {
        for (Instrumentation.ActivityMonitor old : monitors) instrumentation.removeMonitor(old);
        monitors.clear();
        IntentFilter filter = new IntentFilter(action); filter.addCategory(Intent.CATEGORY_OPENABLE); filter.addDataType(type);
        Intent data = file == null ? null : new Intent().setData(Uri.fromFile(file));
        Instrumentation.ActivityMonitor monitor = instrumentation.addMonitor(filter, new Instrumentation.ActivityResult(result, data), true);
        monitors.add(monitor);
    }
    private UiObject2 field(String label) { UiObject2 value = device.wait(Until.findObject(By.desc(label).clazz("android.widget.EditText")), 10000); assertNotNull(label, value); return value; }
    private UiObject2 waitText(String text) { UiObject2 value = device.wait(Until.findObject(By.text(text)), 15000); assertNotNull(text, value); return value; }
    private void waitContains(String text) { assertTrue(text, device.wait(Until.hasObject(By.textContains(text)), 20000)); }
    private void click(String text) {
        for (int attempt = 0; attempt < 3 && !device.hasObject(By.text(text)); attempt++) {
            device.swipe(device.getDisplayWidth() / 2, device.getDisplayHeight() * 4 / 5,
                    device.getDisplayWidth() / 2, device.getDisplayHeight() / 3, 20);
        }
        waitText(text).click();
    }
}
