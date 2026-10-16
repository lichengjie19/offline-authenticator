package com.chengjieli.offlineauth;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.chengjieli.offlineauth.core.Account;
import com.chengjieli.offlineauth.core.AccountTransfer;
import com.chengjieli.offlineauth.core.OtpUriParser;
import com.chengjieli.offlineauth.core.TransferCodec;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Local encrypted file transfer and deliberately revealed, short-lived account QR codes. */
public final class TransferActivity extends Activity {
    private static final int CREATE_FILE = 201, OPEN_FILE = 202;
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int BG = Color.rgb(245,247,250), PANEL = Color.WHITE;
    private static final int ACCENT = Color.rgb(8,127,117), TEXT = Color.rgb(22,43,54);
    private static final int MUTED = Color.rgb(99,119,131), BORDER = Color.rgb(218,228,232);
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Object lifecycle = new Object();
    private final List<Button> controls = new ArrayList<>();
    private VaultStore vault;
    private TextView status;
    private List<Account> accounts = Collections.emptyList();
    private volatile boolean alive = true;
    private boolean resumed, busy, loaded, awaitingImport;
    private volatile int generation;
    private byte[] pendingExport;
    private String initialAccountId;
    private AlertDialog activeDialog, qrDialog;
    private Bitmap qrBitmap;
    private ImageView qrImage;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        // Transfer passwords and QR codes remain protected in every build, including debug.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(BG); getWindow().setNavigationBarColor(BG);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        vault = new VaultStore(this);
        initialAccountId = state == null ? getIntent().getStringExtra("account_id") : null;
        buildScreen();
        loadAccounts(state != null);
    }

    private void buildScreen() {
        LinearLayout root = column(); root.setBackgroundColor(BG);
        root.setPadding(dp(24), dp(16), dp(24), dp(24));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(dp(24) + insets.getSystemWindowInsetLeft(), dp(16) + insets.getSystemWindowInsetTop(),
                    dp(24) + insets.getSystemWindowInsetRight(), dp(24) + insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        setContentView(root); root.requestApplyInsets();
        Button back = button("‹ 返回账号列表", false); back.setOnClickListener(v -> finish());
        root.addView(back, params(-2, 46, 0));
        TextView title = text("备份与转移", 28, TEXT); title.setTypeface(null, Typeface.BOLD);
        root.addView(title, params(-1, -2, 22));
        root.addView(text("在自己的设备之间转移账号。原设备上的账号会保留。", 14, MUTED), params(-1, -2, 10));
        status = text("正在读取本机账号…", 14, ACCENT); root.addView(status, params(-1, -2, 18));
        ScrollView scroll = new ScrollView(this); LinearLayout content = column(); scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        TextView fileTitle = text("加密备份文件", 20, TEXT); fileTitle.setTypeface(null, Typeface.BOLD);
        content.addView(fileTitle, params(-1, -2, 24));
        content.addView(text("用独立密码保护 .oab 文件。另一部设备安装本应用后，可选择文件并输入密码导入。请单独记住密码，忘记后无法解密。", 14, MUTED), params(-1, -2, 10));
        action(content, "导出全部账号", true, () -> showExportPassword(new ArrayList<>(accounts)));
        action(content, "选择账号导出", false, this::chooseExportAccounts);
        action(content, "导入加密备份", false, this::chooseImportFile);
        TextView qrTitle = text("当面扫码转移", 20, TEXT); qrTitle.setTypeface(null, Typeface.BOLD);
        content.addView(qrTitle, params(-1, -2, 30));
        content.addView(text("一次转移一个账号。请用另一部手机的验证器扫描，完成后核对两台设备的验证码。", 14, MUTED), params(-1, -2, 10));
        action(content, "显示账号二维码", false, this::chooseQrAccount);
        content.addView(text("仅使用本地文件，不自动上传或同步。导入只新增账号，重复密钥会跳过，不覆盖已有名称。删除应用前，请先验证备份能够恢复，并保留各网站的恢复码。", 13, MUTED), params(-1, -2, 26));
        setBusy(true, "正在读取本机账号…");
    }

    private void loadAccounts(boolean recreated) {
        final int token = ++generation;
        worker.execute(() -> {
            try {
                List<Account> result = vault.load();
                deliver(token, () -> {
                    accounts = result; loaded = true;
                    setBusy(false, recreated ? "页面已重建，尚未确认的转移已取消。已确认的导入请核对账号列表；本机共有 " + accounts.size() + " 个账号。" : "本机共有 " + accounts.size() + " 个账号");
                    maybeOpenInitialQr();
                });
            } catch (Exception failure) {
                deliver(token, () -> setBusy(false, "无法读取加密账号。原始数据已保留，请返回后重试。"));
            }
        });
    }

    private void chooseExportAccounts() {
        if (accounts.isEmpty()) { toast("还没有可导出的账号"); return; }
        String[] names = labels(accounts); boolean[] checked = new boolean[accounts.size()];
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("选择要导出的账号")
                .setMultiChoiceItems(names, checked, (d, which, selected) -> checked[which] = selected)
                .setNegativeButton("取消", null).setPositiveButton("下一步", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            List<Account> selected = new ArrayList<>();
            for (int index = 0; index < checked.length; index++) if (checked[index]) selected.add(accounts.get(index));
            if (selected.isEmpty()) { toast("请至少选择一个账号"); return; }
            dialog.dismiss(); showExportPassword(selected);
        })); showProtected(dialog);
    }

    private void showExportPassword(List<Account> selected) {
        if (selected.isEmpty()) { toast("还没有可导出的账号"); return; }
        LinearLayout form = form();
        form.addView(text("将导出 " + selected.size() + " 个账号。请设置至少 8 个字符的独立密码。", 14, MUTED));
        EditText password = passwordField(form, "备份密码");
        EditText confirmation = passwordField(form, "再次输入备份密码");
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("设置备份密码").setView(wrap(form))
                .setNegativeButton("取消", null).setPositiveButton("加密并选择位置", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            char[] first = characters(password), second = characters(confirmation);
            if (first.length < 8 || first.length > 256 || !Arrays.equals(first, second)) {
                wipe(first); wipe(second); toast("密码须为 8–256 个字符，且两次输入一致"); return;
            }
            wipe(second); password.setText(""); confirmation.setText(""); dialog.dismiss();
            encryptExport(selected, first);
        }));
        dialog.setOnDismissListener(d -> { password.setText(""); confirmation.setText(""); });
        showProtected(dialog);
    }

    private void encryptExport(List<Account> selected, char[] password) {
        int token = ++generation; setBusy(true, "正在加密备份…");
        worker.execute(() -> {
            byte[] encrypted = null;
            try {
                if (!current(token)) return;
                encrypted = TransferCodec.encrypt(selected, password);
                byte[] ready = encrypted; encrypted = null;
                main.post(() -> {
                    if (!current(token)) { wipe(ready); return; }
                    if (!resumed) {
                        wipe(ready);
                        setBusy(false, "导出已取消，请回到页面重新导出。");
                        return;
                    }
                    pendingExport = ready;
                    Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                            .setType("application/octet-stream").putExtra(Intent.EXTRA_LOCAL_ONLY, true)
                            .putExtra(Intent.EXTRA_TITLE, "offline-authenticator-"
                                    + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(new Date()) + ".oab");
                    try { startActivityForResult(intent, CREATE_FILE); }
                    catch (RuntimeException failure) { wipePendingExport(); setBusy(false, "无法打开文件选择器，请重试。"); }
                });
            } catch (Exception failure) {
                deliver(token, () -> setBusy(false, "无法生成加密备份，请检查密码和账号后重试。"));
            } finally { wipe(password); wipe(encrypted); }
        });
    }

    private void chooseImportFile() {
        awaitingImport = true;
        setBusy(true, "请选择本地 .oab 加密备份文件");
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*").putExtra(Intent.EXTRA_LOCAL_ONLY, true);
        try { startActivityForResult(intent, OPEN_FILE); }
        catch (RuntimeException failure) { awaitingImport = false; setBusy(false, "无法打开文件选择器，请重试。"); }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != CREATE_FILE && request != OPEN_FILE) return;
        if (result != RESULT_OK || data == null || data.getData() == null) {
            awaitingImport = false; wipePendingExport(); setBusy(false, "已取消转移，本机账号未改变。"); return;
        }
        if (request == CREATE_FILE) {
            if (pendingExport == null) { setBusy(false, "操作已取消，请重新导出。"); return; }
            byte[] encrypted = pendingExport; pendingExport = null;
            saveExport(data.getData(), encrypted);
        } else {
            if (!awaitingImport) { setBusy(false, "操作已取消，请重新导入。"); return; }
            awaitingImport = false; showImportPassword(data.getData());
        }
    }

    private void saveExport(Uri uri, byte[] encrypted) {
        int token = ++generation; setBusy(true, "正在保存加密文件…");
        worker.execute(() -> {
            try {
                if (!current(token)) return;
                try (OutputStream output = getContentResolver().openOutputStream(uri, "wt")) {
                    if (output == null) throw new IOException("Output unavailable");
                    for (int offset = 0; offset < encrypted.length; offset += 8192) {
                        if (!current(token)) throw new IOException("Transfer cancelled");
                        output.write(encrypted, offset, Math.min(8192, encrypted.length - offset));
                    }
                    output.flush();
                }
                deliver(token, () -> setBusy(false, "加密备份已保存。请牢记密码，原设备账号已保留。"));
            } catch (Exception failure) {
                deliver(token, () -> setBusy(false, "文件保存未完成，请重新导出。未完成的文件不可用于恢复。"));
            } finally { wipe(encrypted); }
        });
    }

    private void showImportPassword(Uri uri) {
        setBusy(false, "已选择备份文件，请输入解密密码");
        LinearLayout form = form(); EditText password = passwordField(form, "备份解密密码");
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("打开加密备份").setView(wrap(form))
                .setNegativeButton("取消", (d, w) -> setBusy(false, "已取消导入，本机账号未改变。"))
                .setPositiveButton("解密并预览", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            char[] value = characters(password);
            if (value.length < 8 || value.length > 256) { wipe(value); toast("请输入 8–256 个字符的备份密码"); return; }
            password.setText(""); dialog.dismiss(); decryptImport(uri, value);
        }));
        dialog.setOnDismissListener(d -> password.setText("")); showProtected(dialog);
    }

    private void decryptImport(Uri uri, char[] password) {
        int token = ++generation; setBusy(true, "正在解密并检查备份…");
        worker.execute(() -> {
            byte[] encrypted = null;
            try {
                encrypted = readBounded(uri, token);
                if (!current(token)) return;
                List<Account> imported = TransferCodec.decrypt(encrypted, password);
                AccountTransfer.Result preview = AccountTransfer.merge(vault.load(), imported);
                deliver(token, () -> { setBusy(false, "备份已解密，等待确认导入"); showImportPreview(imported, preview); });
            } catch (Exception failure) {
                deliver(token, () -> setBusy(false, "无法导入：密码错误、文件损坏、不受支持或合并后超过 250 个账号。本机账号未改变。"));
            } finally { wipe(password); wipe(encrypted); }
        });
    }

    private void showImportPreview(List<Account> imported, AccountTransfer.Result preview) {
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("确认导入账号")
                .setMessage("新增 " + preview.added + " 个账号\n跳过重复 " + preview.skipped
                        + " 个账号\n\n已有账号及名称会保留。确认时会再次检查最新账号列表。")
                .setNegativeButton("取消", (d, w) -> setBusy(false, "已取消导入，本机账号未改变。"))
                .setPositiveButton("确认导入", (d, w) -> commitImport(imported)).create();
        showProtected(dialog);
    }

    private void commitImport(List<Account> imported) {
        int token = ++generation; setBusy(true, "正在安全合并账号…");
        worker.execute(() -> {
            try {
                final AccountTransfer.Result result;
                synchronized (lifecycle) {
                    if (!current(token)) return;
                    // The store holds its shared storage lock across latest-read, merge and save.
                    result = vault.mergeAndSave(imported);
                }
                deliver(token, () -> {
                    accounts = result.accounts;
                    setBusy(false, "导入完成：新增 " + result.added + " 个，跳过重复 " + result.skipped + " 个。已有账号已保留。");
                });
            } catch (Exception failure) {
                deliver(token, () -> setBusy(false, "导入未完成，请检查存储或账号数量后重试。已有账号未被替换。"));
            }
        });
    }

    private byte[] readBounded(Uri uri, int token) throws IOException {
        try (InputStream input = getContentResolver().openInputStream(uri);
             ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
            if (input == null) throw new IOException("Input unavailable");
            byte[] buffer = new byte[8192]; int count;
            while ((count = input.read(buffer)) != -1) {
                if (!current(token) || bytes.size() > MAX_BYTES - count) throw new IOException("Invalid input size or cancelled transfer");
                bytes.write(buffer, 0, count);
            }
            return bytes.toByteArray();
        }
    }

    private void chooseQrAccount() {
        if (accounts.isEmpty()) { toast("还没有可转移的账号"); return; }
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("选择要转移的账号")
                .setItems(labels(accounts), (d, which) -> generateQr(accounts.get(which)))
                .setNegativeButton("取消", null).create(); showProtected(dialog);
    }

    private void maybeOpenInitialQr() {
        if (!resumed || !loaded || busy || initialAccountId == null) return;
        String id = initialAccountId; initialAccountId = null;
        for (Account account : accounts) if (account.id.equals(id)) { generateQr(account); return; }
        setBusy(false, "该账号已不存在，请返回列表重试。");
    }

    private void generateQr(Account account) {
        int token = ++generation; setBusy(true, "正在生成账号转移二维码…");
        worker.execute(() -> {
            try {
                String uri = OtpUriParser.format(account);
                Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
                hints.put(EncodeHintType.CHARACTER_SET, "UTF-8"); hints.put(EncodeHintType.MARGIN, 4);
                hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
                BitMatrix matrix = new QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 900, 900, hints);
                int[] pixels = new int[900 * 900];
                for (int y = 0; y < 900; y++) for (int x = 0; x < 900; x++) pixels[y * 900 + x] = matrix.get(x, y) ? Color.BLACK : Color.WHITE;
                Bitmap bitmap = Bitmap.createBitmap(pixels, 900, 900, Bitmap.Config.ARGB_8888);
                Arrays.fill(pixels, 0);
                main.post(() -> {
                    if (!current(token) || !resumed) { bitmap.recycle(); if (current(token)) setBusy(false, "二维码展示已取消。"); return; }
                    setBusy(false, "原设备账号已保留"); showQr(account, bitmap);
                });
            } catch (Exception failure) {
                deliver(token, () -> setBusy(false, "此账号无法生成标准二维码，请检查名称，或使用加密文件转移。"));
            }
        });
    }

    private void showQr(Account account, Bitmap bitmap) {
        closeQr(); qrBitmap = bitmap;
        LinearLayout form = form(); form.setGravity(Gravity.CENTER_HORIZONTAL);
        TextView label = text(account.displayTitle(), 16, TEXT); label.setGravity(Gravity.CENTER); form.addView(label);
        qrImage = new ImageView(this); qrImage.setImageBitmap(bitmap); qrImage.setAdjustViewBounds(true);
        qrImage.setContentDescription("敏感账号转移二维码");
        form.addView(qrImage, new LinearLayout.LayoutParams(-1, dp(275)));
        form.addView(text("扫码可复制此账号的验证能力，请仅向自己的设备展示。切到后台后二维码会自动关闭。", 14, MUTED));
        qrDialog = new AlertDialog.Builder(this).setTitle("转移此账号").setView(wrap(form))
                .setPositiveButton("完成并关闭二维码", (d, w) -> closeQr()).create();
        qrDialog.setOnDismissListener(d -> clearQrBitmap());
        showProtected(qrDialog);
    }

    private void closeQr() {
        AlertDialog dialog = qrDialog; qrDialog = null;
        if (dialog != null) dialog.dismiss(); clearQrBitmap();
    }
    private void clearQrBitmap() {
        if (qrImage != null) qrImage.setImageDrawable(null); qrImage = null;
        if (qrBitmap != null) qrBitmap.recycle(); qrBitmap = null;
    }
    @Override protected void onResume() { super.onResume(); resumed = true; maybeOpenInitialQr(); }
    @Override protected void onPause() { resumed = false; closeQr(); super.onPause(); }
    @Override protected void onDestroy() {
        synchronized (lifecycle) { alive = false; generation++; }
        closeQr(); if (activeDialog != null) activeDialog.dismiss();
        wipePendingExport(); accounts = Collections.emptyList(); worker.shutdown();
        super.onDestroy();
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        // Intentionally persist no account contents, transfer passwords or pending operation.
        super.onSaveInstanceState(state);
    }
    private boolean current(int token) { return alive && generation == token && !isFinishing() && !isDestroyed(); }
    private void deliver(int token, Runnable action) { main.post(() -> { if (current(token)) action.run(); }); }
    private void wipePendingExport() { wipe(pendingExport); pendingExport = null; }
    private static void wipe(byte[] value) { if (value != null) Arrays.fill(value, (byte) 0); }
    private static void wipe(char[] value) { if (value != null) Arrays.fill(value, '\0'); }
    private static char[] characters(EditText field) { char[] result = new char[field.length()]; field.getText().getChars(0, result.length, result, 0); return result; }
    private void setBusy(boolean value, String message) {
        busy = value; status.setText(message);
        for (Button control : controls) control.setEnabled(loaded && !busy);
    }
    private static String[] labels(List<Account> values) { String[] result = new String[values.size()]; for (int i = 0; i < values.size(); i++) result[i] = values.get(i).displayTitle(); return result; }
    private void showProtected(AlertDialog dialog) {
        activeDialog = dialog; dialog.setCanceledOnTouchOutside(false);
        if (dialog.getWindow() != null) dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.show();
    }
    private void action(LinearLayout parent, String label, boolean primary, Runnable action) {
        Button button = button(label, primary); controls.add(button);
        button.setOnClickListener(v -> { if (loaded && !busy) action.run(); }); parent.addView(button, params(-1, 54, 12));
    }
    private EditText passwordField(LinearLayout form, String label) {
        form.addView(text(label, 13, MUTED), params(-1, -2, 14));
        EditText field = new EditText(this); field.setSingleLine(true); field.setTextColor(TEXT); field.setTextSize(16);
        field.setContentDescription(label); field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        field.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING); field.setSaveEnabled(false);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        field.setPadding(dp(12), dp(8), dp(12), dp(8)); field.setBackground(shape(PANEL));
        form.addView(field, params(-1, 50, 6)); return field;
    }
    private LinearLayout form() { LinearLayout form = column(); form.setPadding(dp(24), dp(16), dp(24), dp(12)); form.setSaveEnabled(false); return form; }
    private ScrollView wrap(LinearLayout form) { ScrollView scroll = new ScrollView(this); scroll.setSaveEnabled(false); scroll.addView(form); return scroll; }
    private LinearLayout column() { LinearLayout view = new LinearLayout(this); view.setOrientation(LinearLayout.VERTICAL); return view; }
    private TextView text(String value, int size, int color) { TextView view = new TextView(this); view.setText(value); view.setTextSize(size); view.setTextColor(color); view.setLineSpacing(dp(3), 1); return view; }
    private Button button(String label, boolean primary) { Button button = new Button(this); button.setText(label); button.setAllCaps(false); button.setTextColor(primary ? Color.WHITE : ACCENT); button.setTextSize(15); button.setBackground(shape(primary ? ACCENT : PANEL)); button.setStateListAnimator(null); return button; }
    private GradientDrawable shape(int color) { GradientDrawable drawable = new GradientDrawable(); drawable.setColor(color); drawable.setCornerRadius(dp(12)); drawable.setStroke(dp(1), BORDER); return drawable; }
    private LinearLayout.LayoutParams params(int width, int height, int top) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(width < 0 ? width : dp(width), height < 0 ? height : dp(height)); p.topMargin = dp(top); return p; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private void toast(String message) { Toast.makeText(this, message, Toast.LENGTH_LONG).show(); }
}
