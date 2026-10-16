package com.chengjieli.offlineauth;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.hardware.display.DisplayManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Size;
import android.view.Gravity;
import android.view.Surface;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.ComponentActivity;
import androidx.camera.core.Camera;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.CameraState;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Preview;
import androidx.camera.core.UseCaseGroup;
import androidx.camera.core.ViewPort;
import androidx.camera.core.resolutionselector.AspectRatioStrategy;
import androidx.camera.core.resolutionselector.ResolutionSelector;
import androidx.camera.core.resolutionselector.ResolutionStrategy;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.content.ContextCompat;

import com.google.common.util.concurrent.ListenableFuture;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** CameraX owns preview geometry and camera lifecycle. QR decoding stays entirely on this device. */
public final class ScanActivity extends ComponentActivity {
    private static final int CAMERA_PERMISSION = 11;
    private static final int PICK_IMAGE = 12;
    private static final int BACKGROUND = Color.rgb(245, 247, 250);
    private static final int PANEL = Color.WHITE;
    private static final int ACCENT = Color.rgb(8, 127, 117);
    private static final int TEXT = Color.rgb(22, 43, 54);
    private static final int MUTED = Color.rgb(99, 119, 131);
    private static final int BORDER = Color.rgb(218, 228, 232);
    private static final int MAX_IMAGE_BYTES = 12 * 1024 * 1024;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService decoderExecutor = Executors.newSingleThreadExecutor();
    private PreviewView preview;
    private TextView status;
    private Button cameraButton;
    private Button imageButton;
    private ProcessCameraProvider cameraProvider;
    private Camera camera;
    private Preview previewUseCase;
    private ImageAnalysis imageAnalysis;
    private DisplayManager displayManager;
    private int boundRotation = -1;
    private int boundWidth;
    private int boundHeight;
    private volatile boolean resumed;
    private volatile int cameraGeneration;
    private boolean providerLoading;
    private boolean cameraHasError;
    private boolean permissionRequested;
    // False after choosing an image: callbacks may finish loading CameraX, but only an explicit
    // camera button press (or cancelling the picker) may return the screen to live scanning.
    private boolean cameraRequested = true;
    private boolean importingImage;
    private boolean finished;
    private long lastFrameMillis;
    private long lastInvalidCodeMillis;
    private final Runnable rebindForDisplay = () -> {
        if (!resumed || !cameraRequested || importingImage || finished || camera == null || cameraHasError) return;
        if (boundRotation != displayRotation() || boundWidth != preview.getWidth()
                || boundHeight != preview.getHeight()) {
            closeCamera();
            maybeStartCamera();
        }
    };
    private final DisplayManager.DisplayListener displayListener = new DisplayManager.DisplayListener() {
        @Override public void onDisplayAdded(int displayId) {}
        @Override public void onDisplayRemoved(int displayId) {}
        @Override public void onDisplayChanged(int displayId) {
            if (preview.getDisplay() != null && preview.getDisplay().getDisplayId() == displayId) {
                schedulePreviewUpdate();
            }
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (!BuildConfig.DEBUG) getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(BACKGROUND);
        getWindow().setNavigationBarColor(BACKGROUND);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        permissionRequested = state != null && state.getBoolean("permission_requested");
        cameraRequested = state == null || state.getBoolean("camera_requested", true);
        displayManager = (DisplayManager) getSystemService(DISPLAY_SERVICE);
        buildUi();
        if (!cameraRequested) {
            String restored = state == null ? null : state.getString("scanner_status");
            if (restored == null || restored.contains("正在")) {
                restored = "可重新选择本地图片，或打开相机扫描。";
            }
            showCameraError(restored, true);
        }
    }

    private void buildUi() {
        boolean landscape = getResources().getConfiguration().orientation
                == android.content.res.Configuration.ORIENTATION_LANDSCAPE;
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BACKGROUND);
        root.setPadding(dp(24), dp(12), dp(24), dp(20));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(dp(24) + insets.getSystemWindowInsetLeft(),
                    dp(12) + insets.getSystemWindowInsetTop(),
                    dp(24) + insets.getSystemWindowInsetRight(),
                    dp(20) + insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(root);

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        Button back = button("‹", false);
        back.setTextSize(28);
        back.setContentDescription("返回账号列表");
        back.setOnClickListener(v -> finish());
        header.addView(back, new LinearLayout.LayoutParams(dp(48), dp(48)));
        TextView title = text("扫描二维码", 25, TEXT);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(0, -2, 1);
        titleParams.leftMargin = dp(14);
        header.addView(title, titleParams);
        root.addView(header);

        TextView caption = text("将网站提供的验证器二维码放入取景框", 14, MUTED);
        caption.setPadding(0, dp(landscape ? 6 : 20), 0, dp(landscape ? 10 : 18));
        root.addView(caption);

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(landscape ? LinearLayout.HORIZONTAL : LinearLayout.VERTICAL);
        root.addView(body, new LinearLayout.LayoutParams(-1, 0, 1));

        FrameLayout cameraFrame = new FrameLayout(this);
        GradientDrawable frameBackground = new GradientDrawable();
        frameBackground.setColor(PANEL);
        frameBackground.setCornerRadius(dp(18));
        frameBackground.setStroke(dp(1), BORDER);
        cameraFrame.setBackground(frameBackground);
        cameraFrame.setClipToOutline(true);
        preview = new PreviewView(this);
        preview.setImplementationMode(PreviewView.ImplementationMode.COMPATIBLE);
        preview.setScaleType(PreviewView.ScaleType.FILL_CENTER);
        preview.setContentDescription("相机取景画面");
        cameraFrame.addView(preview, new FrameLayout.LayoutParams(-1, -1));
        cameraFrame.addView(new ScanOverlay(), new FrameLayout.LayoutParams(-1, -1));
        body.addView(cameraFrame, landscape ? new LinearLayout.LayoutParams(0, -1, 1)
                : new LinearLayout.LayoutParams(-1, 0, 1));
        preview.addOnLayoutChangeListener((view, left, top, right, bottom,
                oldLeft, oldTop, oldRight, oldBottom) -> {
            if (camera == null) maybeStartCamera();
            else schedulePreviewUpdate();
        });
        preview.getPreviewStreamState().observe(this, state -> {
            if (state == PreviewView.StreamState.STREAMING && resumed && camera != null
                    && !importingImage && !finished) {
                status.setText("将二维码放入取景框，识别后自动返回");
            }
        });

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.VERTICAL);
        controls.setGravity(Gravity.CENTER_VERTICAL);
        if (landscape) controls.setPadding(dp(20), 0, 0, 0);
        body.addView(controls, new LinearLayout.LayoutParams(landscape ? dp(260) : -1,
                landscape ? -1 : -2));
        status = text("正在准备相机…", 14, MUTED);
        status.setGravity(Gravity.CENTER);
        status.setPadding(0, dp(18), 0, dp(12));
        status.setMinHeight(dp(66));
        // A fixed status area prevents changing text from repeatedly resizing/rebinding preview.
        controls.addView(status, new LinearLayout.LayoutParams(-1, dp(84)));

        cameraButton = button("允许使用相机", true);
        cameraButton.setVisibility(View.GONE);
        cameraButton.setOnClickListener(v -> {
            cameraRequested = true;
            if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                closeCamera();
                maybeStartCamera();
            } else if (permissionRequested && !shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)) {
                Intent settings = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:" + getPackageName()));
                startActivity(settings);
            } else {
                requestCameraPermission();
            }
        });
        controls.addView(cameraButton, new LinearLayout.LayoutParams(-1, dp(50)));

        imageButton = button("从本地图片识别", false);
        imageButton.setOnClickListener(v -> selectImage());
        LinearLayout.LayoutParams imageParams = new LinearLayout.LayoutParams(-1, dp(52));
        imageParams.topMargin = dp(10);
        controls.addView(imageButton, imageParams);
        TextView offline = text("仅在本机识别 · 图片和密钥不会上传", 12, MUTED);
        offline.setGravity(Gravity.CENTER);
        offline.setPadding(0, dp(16), 0, 0);
        controls.addView(offline);
        root.requestApplyInsets();
    }

    @Override protected void onResume() {
        super.onResume();
        resumed = true;
        displayManager.registerDisplayListener(displayListener, mainHandler);
        maybeStartCamera();
    }

    @Override protected void onPause() {
        resumed = false;
        displayManager.unregisterDisplayListener(displayListener);
        mainHandler.removeCallbacks(rebindForDisplay);
        closeCamera();
        super.onPause();
    }

    @Override protected void onDestroy() {
        closeCamera();
        decoderExecutor.shutdown();
        super.onDestroy();
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        state.putBoolean("permission_requested", permissionRequested);
        state.putBoolean("camera_requested", cameraRequested);
        state.putString("scanner_status", status.getText().toString());
        super.onSaveInstanceState(state);
    }

    private void requestCameraPermission() {
        permissionRequested = true;
        requestPermissions(new String[]{Manifest.permission.CAMERA}, CAMERA_PERMISSION);
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request == CAMERA_PERMISSION) {
            if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
                maybeStartCamera();
            } else {
                showCameraError("未获得相机权限。可允许相机访问，或从本地图片识别。", true);
            }
        }
    }

    private void maybeStartCamera() {
        if (!resumed || !cameraRequested || isDestroyed() || finished || importingImage || camera != null
                || preview.getDisplay() == null || preview.getWidth() == 0 || preview.getHeight() == 0) return;
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            if (!permissionRequested) requestCameraPermission();
            else showCameraError("需要相机权限才能扫码，也可以选择本地图片。", true);
            return;
        }
        if (cameraProvider == null) {
            if (providerLoading) return;
            providerLoading = true;
            status.setText("正在准备相机…");
            ListenableFuture<ProcessCameraProvider> future = ProcessCameraProvider.getInstance(this);
            future.addListener(() -> {
                providerLoading = false;
                if (isDestroyed() || isFinishing()) return;
                try {
                    cameraProvider = future.get();
                    maybeStartCamera();
                } catch (ExecutionException | RuntimeException failure) {
                    showCameraError("相机不可用，请重试或选择本地二维码图片。", true);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    showCameraError("相机初始化中断，请重试或选择本地图片。", true);
                }
            }, ContextCompat.getMainExecutor(this));
            return;
        }
        try {
            CameraSelector selector;
            if (cameraProvider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) {
                selector = CameraSelector.DEFAULT_BACK_CAMERA;
            } else if (cameraProvider.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA)) {
                selector = CameraSelector.DEFAULT_FRONT_CAMERA;
            } else {
                showCameraError("未找到可用相机，请选择本地二维码图片。", false);
                return;
            }
            int rotation = displayRotation();
            ResolutionSelector previewResolution = new ResolutionSelector.Builder()
                    .setAspectRatioStrategy(AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY)
                    .build();
            ResolutionSelector analysisResolution = new ResolutionSelector.Builder()
                    .setAspectRatioStrategy(AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY)
                    .setResolutionStrategy(new ResolutionStrategy(new Size(1280, 960),
                            ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER))
                    .build();
            previewUseCase = new Preview.Builder()
                    .setResolutionSelector(previewResolution).setTargetRotation(rotation).build();
            previewUseCase.setSurfaceProvider(preview.getSurfaceProvider());
            imageAnalysis = new ImageAnalysis.Builder()
                    .setResolutionSelector(analysisResolution)
                    .setTargetRotation(rotation)
                    .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build();
            final int generation = ++cameraGeneration;
            imageAnalysis.setAnalyzer(decoderExecutor, image -> decodeFrame(image, generation));
            UseCaseGroup.Builder group = new UseCaseGroup.Builder()
                    .addUseCase(previewUseCase).addUseCase(imageAnalysis);
            // The analyzer receives the same center-cropped field of view that the user sees.
            // PreviewView alone owns sensor orientation, display rotation, mirroring and scale.
            ViewPort viewPort = preview.getViewPort();
            if (viewPort != null) group.setViewPort(viewPort);
            camera = cameraProvider.bindToLifecycle(this, selector, group.build());
            boundRotation = rotation;
            boundWidth = preview.getWidth();
            boundHeight = preview.getHeight();
            cameraButton.setVisibility(View.GONE);
            status.setText("正在打开相机…");
            camera.getCameraInfo().getCameraState().observe(this, state -> {
                if (generation != cameraGeneration || !resumed || finished || importingImage) return;
                if (state.getError() != null) {
                    // Recoverable CameraX errors may reconnect automatically. Keep the local
                    // image alternative available without repeatedly rebinding a busy camera.
                    cameraHasError = true;
                    showCameraError("暂时无法使用相机，请重试或选择本地图片。", true);
                } else if (state.getType() == CameraState.Type.OPEN) {
                    cameraHasError = false;
                    cameraButton.setVisibility(View.GONE);
                }
            });
        } catch (Exception failure) {
            closeCamera();
            showCameraError("相机不可用，请重试或选择本地二维码图片。", true);
        }
    }

    private int displayRotation() {
        return preview.getDisplay() == null ? Surface.ROTATION_0 : preview.getDisplay().getRotation();
    }

    private void schedulePreviewUpdate() {
        // 180-degree rotation does not necessarily recreate an Activity. Display changes and
        // split-screen resizing rebuild the shared viewport using CameraX, without custom math.
        mainHandler.removeCallbacks(rebindForDisplay);
        mainHandler.post(rebindForDisplay);
    }

    private void decodeFrame(ImageProxy image, int generation) {
        byte[] luminance;
        int width, height;
        try {
            if (!resumed || generation != cameraGeneration) return;
            long now = SystemClock.elapsedRealtime();
            if (now - lastFrameMillis < 180) return;
            lastFrameMillis = now;
            Rect crop = image.getCropRect();
            width = crop.width();
            height = crop.height();
            if (width <= 0 || height <= 0) return;
            ImageProxy.PlaneProxy plane = image.getPlanes()[0];
            ByteBuffer buffer = plane.getBuffer().duplicate();
            int rowStride = plane.getRowStride(), pixelStride = plane.getPixelStride();
            int start = buffer.position();
            luminance = new byte[width * height];
            for (int y = 0; y < height; y++) {
                int rowStart = start + (crop.top + y) * rowStride + crop.left * pixelStride;
                if (pixelStride == 1) {
                    buffer.position(rowStart);
                    buffer.get(luminance, y * width, width);
                } else {
                    for (int x = 0; x < width; x++) {
                        luminance[y * width + x] = buffer.get(rowStart + x * pixelStride);
                    }
                }
            }
        } catch (RuntimeException invalidFrame) {
            return;
        } finally {
            // Close exactly the ImageProxy, including throttled, stale and malformed frames.
            // CameraX owns the underlying Media.Image and must be allowed to reuse its buffer.
            image.close();
        }
        if (!resumed || generation != cameraGeneration) return;
        // QR detection is rotation independent. Do not rotate the preview or its pixels again.
        String result = QrDecoder.decodeLuminance(luminance, width, height);
        if (result != null) {
            mainHandler.post(() -> {
                if (resumed && generation == cameraGeneration) handleDecoded(result, false);
            });
        }
    }

    private void closeCamera() {
        cameraGeneration++;
        mainHandler.removeCallbacks(rebindForDisplay);
        if (camera != null) camera.getCameraInfo().getCameraState().removeObservers(this);
        if (imageAnalysis != null) imageAnalysis.clearAnalyzer();
        if (cameraProvider != null) {
            if (previewUseCase != null && imageAnalysis != null) cameraProvider.unbind(previewUseCase, imageAnalysis);
            else if (previewUseCase != null) cameraProvider.unbind(previewUseCase);
            else if (imageAnalysis != null) cameraProvider.unbind(imageAnalysis);
        }
        if (previewUseCase != null) previewUseCase.setSurfaceProvider(null);
        camera = null;
        previewUseCase = null;
        imageAnalysis = null;
        cameraHasError = false;
        boundRotation = -1;
    }

    private void showCameraError(String message, boolean retry) {
        if (isFinishing() || isDestroyed()) return;
        status.setText(message);
        boolean permission = checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED;
        cameraButton.setText(permission ? "重新打开相机" : "允许使用相机");
        cameraButton.setVisibility(retry ? View.VISIBLE : View.GONE);
    }

    private void selectImage() {
        if (importingImage || finished) return;
        cameraRequested = false;
        importingImage = true;
        closeCamera();
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("image/*");
        intent.putExtra(Intent.EXTRA_LOCAL_ONLY, true);
        try {
            startActivityForResult(intent, PICK_IMAGE);
        } catch (RuntimeException unavailable) {
            importingImage = false;
            cameraRequested = true;
            status.setText("未找到图片选择器，请使用相机扫描。");
            maybeStartCamera();
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != PICK_IMAGE) return;
        if (result != RESULT_OK || data == null || data.getData() == null) {
            importingImage = false;
            cameraRequested = true;
            maybeStartCamera();
            return;
        }
        Uri uri = data.getData();
        // Do not persist document permissions or store the image in app files.
        cameraRequested = false;
        closeCamera();
        importingImage = true;
        imageButton.setEnabled(false);
        status.setText("正在本机识别图片…");
        decoderExecutor.execute(() -> {
            String decoded = null;
            String error = null;
            Bitmap bitmap = null;
            try {
                byte[] dataBytes = readBoundedImage(uri);
                BitmapFactory.Options options = new BitmapFactory.Options();
                options.inJustDecodeBounds = true;
                BitmapFactory.decodeByteArray(dataBytes, 0, dataBytes.length, options);
                if (options.outWidth <= 0 || options.outHeight <= 0
                        || options.outWidth > 20000 || options.outHeight > 20000) {
                    throw new IOException("Unsupported image dimensions");
                }
                options.inSampleSize = 1;
                while (options.outWidth / options.inSampleSize > 1800
                        || options.outHeight / options.inSampleSize > 1800) {
                    options.inSampleSize *= 2;
                }
                options.inJustDecodeBounds = false;
                options.inPreferredConfig = Bitmap.Config.ARGB_8888;
                bitmap = BitmapFactory.decodeByteArray(dataBytes, 0, dataBytes.length, options);
                if (bitmap == null) throw new IOException("Unsupported image");
                int width = bitmap.getWidth(), height = bitmap.getHeight();
                int[] pixels = new int[width * height];
                bitmap.getPixels(pixels, 0, width, 0, 0, width, height);
                decoded = QrDecoder.decodeArgb(pixels, width, height);
            } catch (IOException | RuntimeException failure) {
                error = "无法读取图片，请选择小于 12 MB 的本地二维码图片。";
            } catch (OutOfMemoryError tooLarge) {
                error = "图片过大，请裁剪到二维码区域后重试。";
            } finally {
                if (bitmap != null) bitmap.recycle();
            }
            final String payload = decoded;
            final String message = error;
            mainHandler.post(() -> {
                if (isFinishing() || isDestroyed() || finished) return;
                importingImage = false;
                imageButton.setEnabled(true);
                if (message != null) status.setText(message);
                else if (payload == null) status.setText("未找到二维码，请选择清晰、完整的二维码图片。");
                else handleDecoded(payload, true);
                if (!finished) {
                    // Keep the import result visible; the user can deliberately restart the camera.
                    cameraButton.setText("重新打开相机");
                    cameraButton.setVisibility(View.VISIBLE);
                }
            });
        });
    }

    private byte[] readBoundedImage(Uri uri) throws IOException {
        try (InputStream input = getContentResolver().openInputStream(uri);
             ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
            if (input == null) throw new IOException("Image unavailable");
            byte[] chunk = new byte[8192];
            int count;
            while ((count = input.read(chunk)) != -1) {
                if (bytes.size() + count > MAX_IMAGE_BYTES) throw new IOException("Image too large");
                bytes.write(chunk, 0, count);
            }
            return bytes.toByteArray();
        }
    }

    private void handleDecoded(String payload, boolean fromImage) {
        if (finished || isFinishing() || isDestroyed()) return;
        if (!QrDecoder.isSupportedTotpUri(payload)) {
            long now = SystemClock.elapsedRealtime();
            if (fromImage || now - lastInvalidCodeMillis > 1800) {
                lastInvalidCodeMillis = now;
                status.setText("这不是 TOTP 验证器二维码，请扫描账号安全设置中的二维码。");
            }
            return;
        }
        finished = true;
        closeCamera();
        setResult(RESULT_OK, new Intent().putExtra("otp_uri", payload));
        finish();
    }

    private TextView text(String label, int size, int color) {
        TextView view = new TextView(this);
        view.setText(label);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setFontFeatureSettings("kern");
        return view;
    }

    private Button button(String label, boolean primary) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(15);
        button.setAllCaps(false);
        button.setTextColor(primary ? Color.WHITE : ACCENT);
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setPadding(dp(12), 0, dp(12), 0);
        GradientDrawable background = new GradientDrawable();
        background.setColor(primary ? ACCENT : PANEL);
        background.setCornerRadius(dp(14));
        if (!primary) background.setStroke(dp(1), BORDER);
        button.setBackground(background);
        return button;
    }

    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }

    private final class ScanOverlay extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        ScanOverlay() { super(ScanActivity.this); setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO); }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float side = Math.min(getWidth() * .78f, getHeight() * .72f);
            float left = (getWidth() - side) / 2, top = (getHeight() - side) / 2;
            float right = left + side, bottom = top + side;
            paint.setColor(0x70040B10);
            paint.setStyle(Paint.Style.FILL);
            canvas.drawRect(0, 0, getWidth(), top, paint);
            canvas.drawRect(0, bottom, getWidth(), getHeight(), paint);
            canvas.drawRect(0, top, left, bottom, paint);
            canvas.drawRect(right, top, getWidth(), bottom, paint);
            paint.setColor(ACCENT);
            paint.setStrokeWidth(dp(3));
            paint.setStrokeCap(Paint.Cap.ROUND);
            float corner = dp(25);
            canvas.drawLine(left, top + corner, left, top, paint);
            canvas.drawLine(left, top, left + corner, top, paint);
            canvas.drawLine(right - corner, top, right, top, paint);
            canvas.drawLine(right, top, right, top + corner, paint);
            canvas.drawLine(left, bottom - corner, left, bottom, paint);
            canvas.drawLine(left, bottom, left + corner, bottom, paint);
            canvas.drawLine(right - corner, bottom, right, bottom, paint);
            canvas.drawLine(right, bottom, right, bottom - corner, paint);
        }
    }
}
