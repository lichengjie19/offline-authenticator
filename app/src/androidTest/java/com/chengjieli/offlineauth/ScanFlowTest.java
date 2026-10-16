package com.chengjieli.offlineauth;

import android.Manifest;
import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.pm.ActivityInfo;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry;
import androidx.test.runner.lifecycle.Stage;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;
import androidx.camera.core.Camera;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.CameraState;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.Preview;
import androidx.camera.view.PreviewView;

import com.chengjieli.offlineauth.core.Account;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

/** Emulator/device tests. Fixture secrets are synthetic test data, never personal credentials. */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public final class ScanFlowTest {
    private Instrumentation instrumentation;
    private Context context;
    private UiDevice device;
    private final List<Activity> activities = new ArrayList<>();
    private final List<Instrumentation.ActivityMonitor> monitors = new ArrayList<>();
    private final List<File> fixtures = new ArrayList<>();
    private List<Account> originalAccounts;

    @Before public void prepare() throws Exception {
        instrumentation = InstrumentationRegistry.getInstrumentation();
        context = instrumentation.getTargetContext();
        device = UiDevice.getInstance(instrumentation);
        assertTrue("Run only against the separate debug app", context.getPackageName().endsWith(".debug"));
        device.wakeUp();
    }

    @After public void cleanUp() throws Exception {
        String foreground = device.getCurrentPackageName();
        if (foreground != null && foreground.endsWith("permissioncontroller")) device.pressBack();
        for (Instrumentation.ActivityMonitor monitor : monitors) instrumentation.removeMonitor(monitor);
        instrumentation.runOnMainSync(() -> {
            for (Activity activity : activities) if (!activity.isDestroyed()) activity.finish();
        });
        instrumentation.waitForIdleSync();
        if (originalAccounts != null) new VaultStore(context).save(originalAccounts);
        for (File fixture : fixtures) fixture.delete();
    }

    @Test public void a_permissionDenialShowsOfflineAlternative() throws Exception {
        // For this branch, revoke CAMERA with adb before starting instrumentation. Revoking the
        // target UID while its instrumentation runs would terminate the test process itself.
        Assume.assumeTrue("Revoke CAMERA before the run to exercise the denial dialog",
                context.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED);
        launch(ScanActivity.class);
        // Google system images use com.google.android.permissioncontroller; AOSP images use
        // com.android.permissioncontroller. The resource suffix is stable across both.
        UiObject2 deny = device.wait(Until.findObject(By.res(Pattern.compile(
                ".*:id/permission_deny(?:_and_dont_ask_again)?_button"))), 8000);
        if (deny != null) deny.click();
        else savePermissionHierarchy("deny-button-missing");
        boolean explanationVisible = device.wait(Until.hasObject(
                By.pkg(context.getPackageName()).textContains("相机权限")), 8000);
        if (!explanationVisible) savePermissionHierarchy("denial-explanation-missing");
        assertTrue("Declining the system dialog must expose the app's permission explanation",
                explanationVisible);
        assertTrue(device.hasObject(By.text("从本地图片识别")));
        assertEquals(PackageManager.PERMISSION_DENIED, context.checkSelfPermission(Manifest.permission.CAMERA));
    }

    @Test public void b_cameraClosesAndReopensAcrossBackground() throws Exception {
        grantCamera();
        ScanActivity scan = launch(ScanActivity.class);
        assertTrue("CameraX preview should stream", waitForCamera(scan, true));
        device.pressHome();
        assertTrue("Backgrounding should release camera use cases", waitForCamera(scan, false));
        Intent resume = new Intent(context, ScanActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        context.startActivity(resume);
        assertTrue("Returning should stream a fresh CameraX preview", waitForCamera(scan, true));
        assertTrue(device.hasObject(By.text("从本地图片识别")));
    }

    @Test public void c_localQrImageAddsAccountAndRejectsUnrelatedQr() throws Exception {
        grantCamera();
        originalAccounts = new VaultStore(context).load();
        String accountName = "scanner-test-" + System.nanoTime() + "@example.test";
        String issuer = "Offline QR Test";
        StringBuilder secretBuilder = new StringBuilder("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        for (char hex : java.util.UUID.randomUUID().toString().replace("-", "").toCharArray()) {
            secretBuilder.append((char) ('A' + Character.digit(hex, 16)));
        }
        String secret = secretBuilder.toString();
        String otp = "otpauth://totp/Offline%20QR%20Test%3A" + accountName
                + "?secret=" + secret + "&issuer=Offline%20QR%20Test&algorithm=SHA1&digits=6&period=30";

        launch(MainActivity.class);
        Instrumentation.ActivityMonitor scanMonitor = instrumentation.addMonitor(ScanActivity.class.getName(), null, false);
        monitors.add(scanMonitor);
        UiObject2 scanButton = device.wait(Until.findObject(By.desc("扫描二维码")), 5000);
        assertNotNull(scanButton);
        scanButton.click();
        Activity scan = instrumentation.waitForMonitorWithTimeout(scanMonitor, 5000);
        assertNotNull("Scanner should open from the main screen", scan);
        activities.add(scan);

        returnPickerImage(makeQr("https://example.test/unrelated"));
        boolean rejectedUnrelatedQr = device.wait(Until.hasObject(By.textContains("这不是 TOTP 验证器二维码")), 5000);
        if (!rejectedUnrelatedQr) saveScannerState(scan, "unrelated-qr-result-missing");
        assertTrue("Unrelated QR result must remain visible until an explicit camera restart", rejectedUnrelatedQr);
        assertFalse(scan.isFinishing());
        instrumentation.runOnMainSync(() -> {
            try {
                assertEquals("Local image result must keep live scanning disabled", false, field("cameraRequested").get(scan));
                assertNull("Local image result must not restart the live camera", field("camera").get(scan));
            } catch (ReflectiveOperationException reflection) { throw new AssertionError(reflection); }
        });

        returnPickerImage(makeQr(otp));
        assertTrue(device.wait(Until.hasObject(By.text("添加扫码账号")), 5000));
        assertTrue(device.hasObject(By.text(accountName)));
        UiObject2 save = device.wait(Until.findObject(By.text("保存账号")), 5000);
        assertNotNull(save);
        save.click();
        assertTrue(device.wait(Until.hasObject(By.text(issuer)), 5000));

        Account added = new VaultStore(context).load().stream()
                .filter(account -> account.name.equals(accountName)).findFirst().orElse(null);
        assertNotNull("Decoded account must reach encrypted persistent storage", added);
        assertEquals(issuer, added.issuer);
        assertEquals(secret, added.secret);
        assertEquals(6, added.digits);
        assertEquals(30, added.period);
        assertEquals("SHA1", added.algorithm);
    }

    @Test public void d_previewKeepsRotationAndAspectRatioInAllFourOrientations() throws Exception {
        grantCamera();
        ScanActivity scan = launch(ScanActivity.class);
        Set<Integer> observedRotations = new HashSet<>();
        int[] orientations = {ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
                ActivityInfo.SCREEN_ORIENTATION_REVERSE_PORTRAIT,
                ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE,
                ActivityInfo.SCREEN_ORIENTATION_REVERSE_LANDSCAPE};
        try {
            for (int orientation : orientations) {
                final ScanActivity beforeRotation = scan;
                instrumentation.runOnMainSync(() -> beforeRotation.setRequestedOrientation(orientation));
                scan = waitForResumedScanner(orientation, observedRotations);
                assertNotNull("Scanner must survive orientation change " + orientation, scan);
                if (!activities.contains(scan)) activities.add(scan);
                assertTrue("Preview must stream after rotation " + orientation, waitForCamera(scan, true));
                awaitAppliedPreviewRotation(scan);
                final ScanActivity current = scan;
                instrumentation.runOnMainSync(() -> {
                    try {
                        PreviewView view = (PreviewView) field("preview").get(current);
                        Preview preview = (Preview) field("previewUseCase").get(current);
                        ImageAnalysis analysis = (ImageAnalysis) field("imageAnalysis").get(current);
                        Camera camera = (Camera) field("camera").get(current);
                        int rotation = view.getDisplay().getRotation();
                        observedRotations.add(rotation);
                        assertEquals(rotation, preview.getTargetRotation());
                        assertEquals(rotation, analysis.getTargetRotation());
                        assertEquals(PreviewView.ScaleType.FILL_CENTER, view.getScaleType());
                        assertEquals(PreviewView.ImplementationMode.COMPATIBLE, view.getImplementationMode());
                        assertTrue("App must not add a second view transform", view.getMatrix().isIdentity());

                        Matrix sensorToView = view.getSensorToViewTransform();
                        assertNotNull("CameraX should publish preview geometry", sensorToView);
                        float[] matrix = new float[9];
                        sensorToView.getValues(matrix);
                        double xLength = Math.hypot(matrix[Matrix.MSCALE_X], matrix[Matrix.MSKEW_Y]);
                        double yLength = Math.hypot(matrix[Matrix.MSKEW_X], matrix[Matrix.MSCALE_Y]);
                        assertTrue("Preview must have nonzero scale", xLength > 0 && yLength > 0);
                        assertEquals("Sensor pixels must remain square, with no horizontal stretch",
                                1.0, xLength / yLength, 0.03);
                        double dot = matrix[Matrix.MSCALE_X] * matrix[Matrix.MSKEW_X]
                                + matrix[Matrix.MSKEW_Y] * matrix[Matrix.MSCALE_Y];
                        assertEquals("Axes must stay perpendicular, with no shear", 0.0,
                                dot / (xLength * yLength), 0.002);
                        if (camera.getCameraInfo().getLensFacing() == CameraSelector.LENS_FACING_BACK) {
                            double actual = (Math.toDegrees(Math.atan2(matrix[Matrix.MSKEW_Y],
                                    matrix[Matrix.MSCALE_X])) + 360) % 360;
                            int expected = camera.getCameraInfo().getSensorRotationDegrees(rotation);
                            double difference = Math.abs(actual - expected);
                            assertTrue("Preview must apply sensor rotation once: expected " + expected
                                    + ", actual " + actual, Math.min(difference, 360 - difference) < 1.0);
                        }
                    } catch (ReflectiveOperationException reflection) { throw new AssertionError(reflection); }
                });
            }
            assertEquals("All four display rotations must be exercised", 4, observedRotations.size());
        } finally {
            final ScanActivity current = scan;
            if (current != null && !current.isDestroyed()) {
                instrumentation.runOnMainSync(current::finish);
            }
        }
    }

    private <T extends Activity> T launch(Class<T> activityClass) {
        Intent intent = new Intent(context, activityClass).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        // Camera preview produces frame callbacks continuously. An ActivityMonitor waits for
        // creation without MonitoringInstrumentation.startActivitySync's global-idle heuristic.
        Instrumentation.ActivityMonitor monitor = instrumentation.addMonitor(activityClass.getName(), null, false);
        context.startActivity(intent);
        Activity activity = instrumentation.waitForMonitorWithTimeout(monitor, 10000);
        instrumentation.removeMonitor(monitor);
        assertNotNull("Activity should be created: " + activityClass.getSimpleName(), activity);
        activities.add(activity);
        return activityClass.cast(activity);
    }

    private void grantCamera() throws Exception {
        try (ParcelFileDescriptor result = instrumentation.getUiAutomation().executeShellCommand(
                "pm grant " + context.getPackageName() + " android.permission.CAMERA");
             InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(result)) {
            byte[] buffer = new byte[512];
            while (input.read(buffer) != -1) { /* Wait for the shell command to complete. */ }
        }
        assertEquals(PackageManager.PERMISSION_GRANTED, context.checkSelfPermission(Manifest.permission.CAMERA));
    }

    private boolean waitForCamera(ScanActivity activity, boolean open) throws Exception {
        Field cameraField = field("camera"), previewField = field("preview");
        Field analysis = field("imageAnalysis"), previewUseCase = field("previewUseCase");
        long deadline = SystemClock.uptimeMillis() + 10000;
        while (SystemClock.uptimeMillis() < deadline) {
            AtomicBoolean matches = new AtomicBoolean();
            instrumentation.runOnMainSync(() -> {
                try {
                    Camera camera = (Camera) cameraField.get(activity);
                    PreviewView preview = (PreviewView) previewField.get(activity);
                    Preview useCase = (Preview) previewUseCase.get(activity);
                    CameraState state = camera == null ? null : camera.getCameraInfo().getCameraState().getValue();
                    matches.set(open ? camera != null && state != null && state.getType() == CameraState.Type.OPEN
                            && preview.getPreviewStreamState().getValue() == PreviewView.StreamState.STREAMING
                            && preview.getSensorToViewTransform() != null && useCase != null
                            && useCase.getTargetRotation() == preview.getDisplay().getRotation()
                            : camera == null && analysis.get(activity) == null && previewUseCase.get(activity) == null);
                } catch (IllegalAccessException inaccessible) { throw new AssertionError(inaccessible); }
            });
            if (matches.get()) return true;
            SystemClock.sleep(60);
        }
        return false;
    }

    private ScanActivity waitForResumedScanner(int requestedOrientation, Set<Integer> alreadyObserved) {
        long deadline = SystemClock.uptimeMillis() + 10000;
        while (SystemClock.uptimeMillis() < deadline) {
            AtomicReference<ScanActivity> resumed = new AtomicReference<>();
            instrumentation.runOnMainSync(() -> {
                for (Activity activity : ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)) {
                    if (activity instanceof ScanActivity && activity.getRequestedOrientation() == requestedOrientation
                            && !activity.isDestroyed() && !activity.isChangingConfigurations()
                            && !alreadyObserved.contains(activity.getWindowManager().getDefaultDisplay().getRotation())) {
                        boolean portrait = requestedOrientation == ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
                                || requestedOrientation == ActivityInfo.SCREEN_ORIENTATION_REVERSE_PORTRAIT;
                        int configuration = activity.getResources().getConfiguration().orientation;
                        if (configuration == (portrait ? android.content.res.Configuration.ORIENTATION_PORTRAIT
                                : android.content.res.Configuration.ORIENTATION_LANDSCAPE)) {
                            resumed.set((ScanActivity) activity);
                        }
                    }
                }
            });
            if (resumed.get() != null) return resumed.get();
            SystemClock.sleep(60);
        }
        return null;
    }

    private void awaitAppliedPreviewRotation(ScanActivity activity) throws Exception {
        Field cameraField = field("camera"), previewField = field("preview");
        AtomicReference<String> lastGeometry = new AtomicReference<>("No transformation metadata yet");
        AtomicReference<String> firstPendingGeometry = new AtomicReference<>();
        long deadline = SystemClock.uptimeMillis() + 10000;
        while (SystemClock.uptimeMillis() < deadline) {
            AtomicBoolean applied = new AtomicBoolean();
            instrumentation.runOnMainSync(() -> {
                try {
                    Camera camera = (Camera) cameraField.get(activity);
                    PreviewView view = (PreviewView) previewField.get(activity);
                    if (camera == null || view.getDisplay() == null) return;
                    Matrix transform = view.getSensorToViewTransform();
                    if (transform == null) return;
                    int rotation = view.getDisplay().getRotation();
                    int expected = camera.getCameraInfo().getSensorRotationDegrees(rotation);
                    float[] matrix = new float[9];
                    transform.getValues(matrix);
                    double actual = (Math.toDegrees(Math.atan2(matrix[Matrix.MSKEW_Y],
                            matrix[Matrix.MSCALE_X])) + 360) % 360;
                    lastGeometry.set("display=" + rotation + ", expected=" + expected + ", actual=" + actual);
                    double delta = Math.abs(actual - expected);
                    applied.set(camera.getCameraInfo().getLensFacing() != CameraSelector.LENS_FACING_BACK
                            || Math.min(delta, 360 - delta) < 1.0);
                    if (!applied.get()) firstPendingGeometry.compareAndSet(null, lastGeometry.get());
                } catch (IllegalAccessException inaccessible) { throw new AssertionError(inaccessible); }
            });
            if (applied.get()) {
                if (firstPendingGeometry.get() != null) System.out.println("CameraX metadata settled: "
                        + firstPendingGeometry.get() + " -> " + lastGeometry.get());
                return;
            }
            SystemClock.sleep(60);
        }
        // CameraX 1.5.3 retains its previous PreviewTransformation until the new
        // SurfaceRequest listener delivers metadata; STREAMING alone is not a rotation fence.
        fail("CameraX did not apply the required preview rotation: " + lastGeometry.get());
    }

    private void savePermissionHierarchy(String reason) throws Exception {
        File directory = context.getExternalFilesDir("test-evidence");
        assertNotNull("Diagnostic directory must be available", directory);
        if (!directory.isDirectory()) assertTrue(directory.mkdirs());
        File hierarchy = new File(directory, "permission-" + reason + ".xml");
        device.dumpWindowHierarchy(hierarchy);
        System.out.println("Permission diagnostic: package=" + device.getCurrentPackageName()
                + ", hierarchy=" + hierarchy.getAbsolutePath());
    }

    private void saveScannerState(Activity scan, String reason) throws Exception {
        File directory = context.getExternalFilesDir("test-evidence");
        assertNotNull(directory);
        if (!directory.isDirectory()) assertTrue(directory.mkdirs());
        File hierarchy = new File(directory, "scanner-" + reason + ".xml");
        device.dumpWindowHierarchy(hierarchy);
        instrumentation.runOnMainSync(() -> {
            try {
                android.widget.TextView status = (android.widget.TextView) field("status").get(scan);
                System.out.println("Scanner diagnostic: cameraRequested=" + field("cameraRequested").get(scan)
                        + ", importingImage=" + field("importingImage").get(scan)
                        + ", providerLoading=" + field("providerLoading").get(scan)
                        + ", cameraBound=" + (field("camera").get(scan) != null)
                        + ", status=" + status.getText() + ", hierarchy=" + hierarchy.getAbsolutePath());
            } catch (ReflectiveOperationException reflection) { throw new AssertionError(reflection); }
        });
    }

    private Field field(String name) throws NoSuchFieldException {
        Field field = ScanActivity.class.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private void returnPickerImage(File fixture) throws Exception {
        IntentFilter picker = new IntentFilter(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.addDataType("image/*");
        Instrumentation.ActivityMonitor monitor = instrumentation.addMonitor(picker,
                new Instrumentation.ActivityResult(Activity.RESULT_OK, new Intent().setData(Uri.fromFile(fixture))), true);
        monitors.add(monitor);
        UiObject2 choose = device.wait(Until.findObject(By.text("从本地图片识别")), 5000);
        assertNotNull(choose);
        choose.click();
        assertTrue("System image picker should be invoked", instrumentation.checkMonitorHit(monitor, 1));
        instrumentation.removeMonitor(monitor);
        monitors.remove(monitor);
    }

    private File makeQr(String text) throws Exception {
        BitMatrix qr = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 800, 800);
        int[] pixels = new int[800 * 800];
        for (int y = 0; y < 800; y++) for (int x = 0; x < 800; x++) {
            pixels[y * 800 + x] = qr.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
        }
        Bitmap bitmap = Bitmap.createBitmap(pixels, 800, 800, Bitmap.Config.ARGB_8888);
        File image = File.createTempFile("qr-test-", ".png", context.getCacheDir());
        fixtures.add(image);
        try (FileOutputStream output = new FileOutputStream(image)) {
            assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output));
        } finally { bitmap.recycle(); }
        return image;
    }
}
