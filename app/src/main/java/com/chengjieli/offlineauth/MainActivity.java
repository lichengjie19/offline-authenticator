package com.chengjieli.offlineauth;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import android.widget.Toast;

import com.chengjieli.offlineauth.core.Account;
import com.chengjieli.offlineauth.core.OtpUriParser;
import com.chengjieli.offlineauth.core.Totp;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(245, 247, 250), PANEL = Color.WHITE;
    private static final int ACCENT = Color.rgb(8, 127, 117), TEXT = Color.rgb(22, 43, 54);
    private static final int MUTED = Color.rgb(99, 119, 131), BORDER = Color.rgb(218, 228, 232);
    private static final int SCAN_REQUEST = 110;
    private final Handler clock = new Handler(Looper.getMainLooper());
    private final List<Account> accounts = new ArrayList<>();
    private final List<Card> cards = new ArrayList<>();
    private VaultStore vault;
    private LinearLayout root, list;
    private TextView count;
    private boolean loadFailed;
    private String query = "";
    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            refreshCodes();
            clock.postDelayed(this, 1000 - System.currentTimeMillis() % 1000);
        }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (!BuildConfig.DEBUG) getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        vault = new VaultStore(this);
        try { accounts.addAll(vault.load()); } catch (Exception error) { loadFailed = true; }
        buildScreen();
        if (loadFailed) showStorageError();
    }

    private void buildScreen() {
        root = column(); root.setBackgroundColor(BG);
        root.setPadding(dp(24), dp(16), dp(24), dp(12));
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(dp(24) + insets.getSystemWindowInsetLeft(), dp(16) + insets.getSystemWindowInsetTop(),
                dp(24) + insets.getSystemWindowInsetRight(), dp(12) + insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        setContentView(root); root.requestApplyInsets();
        LinearLayout top = row();
        TextView brand = text("OFFLINE  /  AUTHENTICATOR", 10, ACCENT);
        brand.setLetterSpacing(0.16f); brand.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        top.addView(brand, new LinearLayout.LayoutParams(0, dp(36), 1)); brand.setGravity(Gravity.CENTER_VERTICAL);
        Button help = button("更多", false); help.setTextSize(12); help.setOnClickListener(v -> showAppMenu(v));
        top.addView(help, new LinearLayout.LayoutParams(dp(90), dp(40))); root.addView(top);
        TextView title = text("离线验证器", 30, TEXT); title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(title, margins(-1, -2, 0, 14, 0, 6));
        root.addView(text("密钥留在此设备，验证码随时可用。", 13, MUTED));
        TextView badge = text("●  纯离线     ·     本机加密存储", 11, ACCENT);
        badge.setPadding(dp(12), dp(8), dp(12), dp(8)); badge.setBackground(shape(Color.rgb(230, 244, 239), 8, 0));
        root.addView(badge, margins(-2, -2, 0, 18, 0, 20));

        EditText search = new EditText(this); search.setSingleLine(true); search.setTextSize(14);
        search.setTextColor(TEXT); search.setHintTextColor(MUTED); search.setHint("搜索服务或账号");
        search.setContentDescription("搜索服务或账号");
        search.setPadding(dp(16), 0, dp(16), 0); search.setBackground(shape(PANEL, 12, BORDER));
        search.setInputType(InputType.TYPE_CLASS_TEXT); search.setSaveEnabled(false);
        root.addView(search, margins(-1, dp(48), 0, 0, 0, 16));
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s,int st,int c,int a) {}
            public void onTextChanged(CharSequence s,int st,int b,int c) { query = s.toString(); renderAccounts(); }
            public void afterTextChanged(Editable e) {}
        });
        LinearLayout accountHeader = row();
        count = text("", 12, MUTED); count.setLetterSpacing(.05f);
        accountHeader.addView(count, new LinearLayout.LayoutParams(0, -2, 1));
        Button transfer = button("账号转移", false); transfer.setTextSize(12);
        transfer.setOnClickListener(v -> openTransfer(null));
        accountHeader.addView(transfer, new LinearLayout.LayoutParams(dp(100), dp(40)));
        root.addView(accountHeader, margins(-1, -2, 0, 0, 0, 12));
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true); scroll.setClipToPadding(false);
        list = column(); scroll.addView(list); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        LinearLayout actions = row();
        Button scan = button("＋ 扫描二维码", true); scan.setContentDescription("扫描二维码");
        scan.setOnClickListener(v -> { if (ready()) startActivityForResult(new Intent(this, ScanActivity.class), SCAN_REQUEST); });
        actions.addView(scan, new LinearLayout.LayoutParams(0, dp(54), 1));
        Button manual = button("手动添加", false); manual.setOnClickListener(v -> { if (ready()) showManual(); });
        actions.addView(manual, margins(dp(108), dp(54), 10, 0, 0, 0));
        root.addView(actions, margins(-1, -2, 0, 16, 0, 0));
        renderAccounts();
    }

    private boolean ready() { if (loadFailed) showStorageError(); return !loadFailed; }

    private void renderAccounts() {
        if (list == null) return;
        list.removeAllViews(); cards.clear();
        count.setText("我的账号  /  " + accounts.size());
        String match = query.trim().toLowerCase(Locale.ROOT);
        for (Account account : accounts) {
            if ((account.issuer + " " + account.name).toLowerCase(Locale.ROOT).contains(match)) {
                Card card = new Card(account); cards.add(card);
                list.addView(card.layout, margins(-1, -2, 0, 0, 0, 12));
            }
        }
        if (cards.isEmpty()) {
            LinearLayout empty = column(); empty.setGravity(Gravity.CENTER); empty.setPadding(dp(20), dp(24), dp(20), dp(24));
            ImageView shield = new ImageView(this); shield.setImageResource(R.drawable.ic_shield);
            empty.addView(shield, new LinearLayout.LayoutParams(dp(84), dp(84)));
            TextView heading = text(loadFailed ? "无法读取本机账号" : accounts.isEmpty() ? "添加你的第一个账号" : "没有匹配的账号", 20, TEXT);
            heading.setGravity(Gravity.CENTER); heading.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            empty.addView(heading, margins(-1, -2, 0, 12, 0, 10));
            TextView desc = text(loadFailed ? "原始数据已保留，请勿清除应用数据。" : accounts.isEmpty() ?
                "在网站开启两步验证后，扫描它提供的\n二维码，即可在这里生成动态验证码。" : "试试其他服务名称或账号。", 13, MUTED);
            desc.setGravity(Gravity.CENTER); desc.setLineSpacing(dp(5), 1); empty.addView(desc);
            list.addView(empty, new LinearLayout.LayoutParams(-1, -1));
        }
        refreshCodes();
    }

    private final class Card {
        final Account account;
        final LinearLayout layout;
        final TextView code, remaining;
        final CountdownRing ring;
        Card(Account account) {
            this.account = account; layout = column(); layout.setPadding(dp(18), dp(16), dp(18), dp(14));
            layout.setBackground(shape(PANEL, 18, BORDER));
            LinearLayout heading = row();
            String service = account.issuer.isEmpty() ? "验证账号" : account.issuer;
            TextView icon = text(service.substring(0, service.offsetByCodePoints(0, 1)).toUpperCase(Locale.ROOT), 20, ACCENT);
            icon.setGravity(Gravity.CENTER); icon.setBackground(shape(Color.rgb(230, 244, 239), 12, 0));
            heading.addView(icon, new LinearLayout.LayoutParams(dp(42), dp(42)));
            LinearLayout labels = column();
            TextView issuer = text(service, 17, TEXT); issuer.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            issuer.setSingleLine(true); issuer.setEllipsize(android.text.TextUtils.TruncateAt.END); labels.addView(issuer);
            TextView name = text(account.name, 12, MUTED); name.setSingleLine(true); name.setEllipsize(android.text.TextUtils.TruncateAt.END);
            labels.addView(name, margins(-1, -2, 0, 4, 0, 0));
            LinearLayout.LayoutParams labelParams = new LinearLayout.LayoutParams(0, -2, 1); labelParams.leftMargin = dp(12);
            heading.addView(labels, labelParams);
            TextView more = text("⋮", 26, MUTED); more.setGravity(Gravity.CENTER); more.setContentDescription("管理 " + service + " " + account.name);
            more.setOnClickListener(v -> accountMenu(v, account)); heading.addView(more, new LinearLayout.LayoutParams(dp(40), dp(48)));
            layout.addView(heading);
            LinearLayout value = row();
            code = text("", 34, TEXT); code.setTypeface(Typeface.MONOSPACE, Typeface.BOLD); code.setLetterSpacing(.06f);
            code.setAutoSizeTextTypeUniformWithConfiguration(22, 34, 1, android.util.TypedValue.COMPLEX_UNIT_SP);
            code.setSingleLine(true); code.setGravity(Gravity.CENTER_VERTICAL); code.setOnClickListener(v -> copyCode(account));
            code.setContentDescription("验证码，点按复制"); value.addView(code, new LinearLayout.LayoutParams(0, dp(58), 1));
            ring = new CountdownRing(); value.addView(ring, new LinearLayout.LayoutParams(dp(45), dp(45)));
            layout.addView(value, margins(-1, -2, 0, 16, 0, 0));
            LinearLayout footer = row(); remaining = text("", 11, MUTED);
            footer.addView(remaining, new LinearLayout.LayoutParams(0, -2, 1));
            Button copy = button("复制", false); copy.setTextSize(11); copy.setOnClickListener(v -> copyCode(account));
            footer.addView(copy, new LinearLayout.LayoutParams(dp(62), dp(38))); layout.addView(footer);
        }
        void update(long now) {
            String raw = Totp.generate(account, now);
            int middle = raw.length() / 2; code.setText(raw.substring(0, middle) + " " + raw.substring(middle));
            int left = Totp.remaining(account, now);
            remaining.setText(account.digits + " 位动态码 · " + left + " 秒后更新");
            ring.left = left; ring.period = account.period; ring.invalidate();
            code.setTextColor(left <= 5 ? Color.rgb(160, 88, 13) : TEXT);
        }
    }

    private final class CountdownRing extends View {
        int left, period = 30;
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        final RectF oval = new RectF();
        CountdownRing() { super(MainActivity.this); setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO); }
        @Override protected void onDraw(Canvas c) {
            super.onDraw(c); float size = Math.min(getWidth(), getHeight()), edge = dp(3);
            oval.set(edge, edge, size-edge, size-edge);
            paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(dp(3)); paint.setColor(BORDER); c.drawOval(oval, paint);
            paint.setColor(left <= 5 ? Color.rgb(160,88,13) : ACCENT); paint.setStrokeCap(Paint.Cap.ROUND);
            c.drawArc(oval, -90, 360f * left / period, false, paint);
            paint.setStyle(Paint.Style.FILL); paint.setTextSize(dp(13)); paint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
            paint.setTextAlign(Paint.Align.CENTER); c.drawText(String.valueOf(left), size / 2, size / 2 - (paint.ascent()+paint.descent())/2, paint);
        }
    }

    private void refreshCodes() {
        long now = System.currentTimeMillis() / 1000;
        for (Card card : cards) card.update(now);
    }
    @Override protected void onResume() {
        super.onResume();
        boolean previousFailure = loadFailed;
        try {
            List<Account> fresh = vault.load();
            accounts.clear(); accounts.addAll(fresh); loadFailed = false;
        } catch (Exception error) {
            loadFailed = true; accounts.clear();
            if (!previousFailure) showStorageError();
        }
        renderAccounts(); clock.removeCallbacks(ticker); ticker.run();
    }
    @Override protected void onPause() {
        super.onPause(); clock.removeCallbacks(ticker);
        for (Card card : cards) card.code.setText("••• •••");
    }
    @Override protected void onDestroy() { clock.removeCallbacks(ticker); super.onDestroy(); }

    private void copyCode(Account account) {
        String value = Totp.generate(account, System.currentTimeMillis()/1000);
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("离线验证器动态码", value);
        if (Build.VERSION.SDK_INT >= 33) { PersistableBundle flags = new PersistableBundle(); flags.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true); clip.getDescription().setExtras(flags); }
        clipboard.setPrimaryClip(clip); toast("验证码已复制");
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            try {
                ClipData current = clipboard.getPrimaryClip();
                if (current != null && current.getItemCount() == 1 && "离线验证器动态码".contentEquals(current.getDescription().getLabel())
                    && value.contentEquals(current.getItemAt(0).getText())) {
                    if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip();
                    else clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
                }
            } catch (RuntimeException ignored) { /* A background app may not read the clipboard. */ }
        }, 30_000);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == SCAN_REQUEST && result == RESULT_OK && data != null && ready()) {
            try { showConfirm(OtpUriParser.parse(data.getStringExtra("otp_uri"))); }
            catch (IllegalArgumentException error) { new AlertDialog.Builder(this).setTitle("无法添加二维码").setMessage(error.getMessage()).setPositiveButton("知道了", null).show(); }
        }
    }

    private void showConfirm(Account account) {
        LinearLayout form = form();
        form.addView(text("请核对服务和账号。密钥仅加密保存在本机。", 13, MUTED));
        EditText issuer = field(form, "服务名称", account.issuer, false);
        EditText name = field(form, "账号", account.name, false);
        form.addView(text(account.algorithm + "  ·  " + account.digits + " 位  ·  " + account.period + " 秒", 12, MUTED));
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("添加扫码账号").setView(wrap(form))
            .setNegativeButton("取消", null).setPositiveButton("保存账号", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                Account changed = new Account(account.id, issuer.getText().toString(), name.getText().toString(), account.secret, account.algorithm, account.digits, account.period);
                if (add(changed)) dialog.dismiss();
            } catch (IllegalArgumentException e) { toast(e.getMessage()); }
        })); protectDialog(dialog); dialog.show();
    }

    private void showManual() {
        LinearLayout form = form();
        EditText issuer = field(form, "服务名称（如 GitHub）", "", false);
        EditText name = field(form, "账号名称或邮箱", "", false);
        EditText secret = field(form, "设置密钥（Base32）", "", true);
        form.addView(text("输入网站提供的 setup key，支持空格分组。", 12, MUTED));
        TextView advanced = text("高级选项  ▾", 13, ACCENT); advanced.setPadding(0,dp(18),0,dp(12)); form.addView(advanced);
        LinearLayout options = column(); options.setVisibility(View.GONE); form.addView(options);
        options.addView(text("算法", 12, MUTED)); Spinner algorithm = spinner(new String[]{"SHA1", "SHA256", "SHA512"}); options.addView(algorithm);
        options.addView(text("验证码位数", 12, MUTED)); Spinner digits = spinner(new String[]{"6", "8"}); options.addView(digits);
        EditText period = field(options, "刷新周期（15–120 秒）", "30", false); period.setInputType(InputType.TYPE_CLASS_NUMBER);
        advanced.setOnClickListener(v -> options.setVisibility(options.getVisibility() == View.GONE ? View.VISIBLE : View.GONE));
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("手动添加账号").setView(wrap(form))
            .setNegativeButton("取消", null).setPositiveButton("保存账号", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                Account account = Account.create(issuer.getText().toString(), name.getText().toString(), secret.getText().toString(),
                    algorithm.getSelectedItem().toString(), Integer.parseInt(digits.getSelectedItem().toString()), Integer.parseInt(period.getText().toString()));
                if (add(account)) { secret.setText(""); dialog.dismiss(); }
            } catch (NumberFormatException e) { toast("请输入有效的刷新周期"); }
            catch (IllegalArgumentException e) { toast(e.getMessage()); }
        })); protectDialog(dialog); dialog.show();
    }

    private boolean add(Account account) {
        if (accounts.size() >= 250) { toast("最多保存 250 个账号"); return false; }
        for (Account existing : accounts) {
            if (existing.secret.equals(account.secret) && existing.algorithm.equals(account.algorithm) && existing.digits == account.digits && existing.period == account.period) {
                toast("这个验证密钥已经添加过了"); return false;
            }
        }
        List<Account> changed = new ArrayList<>(accounts); changed.add(account);
        if (!persist(changed)) return false;
        toast("账号已加密保存"); return true;
    }

    private boolean persist(List<Account> changed) {
        if (!ready()) return false;
        try { vault.save(changed); accounts.clear(); accounts.addAll(changed); renderAccounts(); return true; }
        catch (Exception error) {
            new AlertDialog.Builder(this).setTitle("保存未完成").setMessage("无法写入加密存储，账号列表未改变。请检查设备剩余空间后重试。")
                .setPositiveButton("知道了", null).show(); return false;
        }
    }

    private void accountMenu(View anchor, Account account) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add("编辑名称").setOnMenuItemClickListener(item -> { rename(account); return true; });
        menu.getMenu().add("转移此账号").setOnMenuItemClickListener(item -> { openTransfer(account.id); return true; });
        menu.getMenu().add("删除账号").setOnMenuItemClickListener(item -> {
            new AlertDialog.Builder(this).setTitle("删除这个账号？")
                .setMessage("删除后，本机将无法为「" + (account.issuer.isEmpty() ? account.name : account.issuer) + "」生成验证码。请先确认你有其他验证方式或网站恢复码。")
                .setNegativeButton("取消", null).setPositiveButton("确认删除", (d,w) -> {
                    List<Account> changed = new ArrayList<>(accounts); changed.removeIf(a -> a.id.equals(account.id)); persist(changed);
                }).show(); return true;
        }); menu.show();
    }

    private void rename(Account account) {
        LinearLayout form = form(); EditText issuer = field(form, "服务名称", account.issuer, false);
        EditText name = field(form, "账号", account.name, false);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("编辑名称").setView(wrap(form)).setNegativeButton("取消",null).setPositiveButton("保存",null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                Account updated = new Account(account.id, issuer.getText().toString(), name.getText().toString(),account.secret,account.algorithm,account.digits,account.period);
                List<Account> changed = new ArrayList<>(accounts);
                for (int i=0;i<changed.size();i++) if (changed.get(i).id.equals(account.id)) changed.set(i,updated);
                if (persist(changed)) dialog.dismiss();
            } catch (IllegalArgumentException e) { toast(e.getMessage()); }
        })); protectDialog(dialog); dialog.show();
    }

    private void openTransfer(String accountId) {
        if (!ready()) return;
        Intent transfer = new Intent(this, TransferActivity.class);
        if (accountId != null) transfer.putExtra("account_id", accountId);
        startActivity(transfer);
    }

    private void showAppMenu(View anchor) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add("备份与转移").setOnMenuItemClickListener(item -> { openTransfer(null); return true; });
        menu.getMenu().add("使用说明").setOnMenuItemClickListener(item -> { showHelp(); return true; });
        menu.show();
    }

    private void showHelp() {
        new AlertDialog.Builder(this).setTitle("使用离线验证器")
            .setMessage("1. 在网站的安全设置中开启身份验证器 / TOTP。\n2. 扫描网站提供的二维码，或手动输入设置密钥。\n3. 将这里的动态验证码填回网站，完成绑定。\n\n账号转移：可导出密码保护的加密备份，在新手机导入；也可在账号菜单选择“转移此账号”，让另一部手机扫描二维码。转移会复制账号，原设备保留原账号。\n\n验证码不正确？请开启手机的自动设置日期与时间，等待新验证码后重试。\n\n应用没有网络权限，也没有云同步。卸载或清除数据前，请先导出备份并记住备份密码，同时保留网站恢复码。\n\n支持标准 TOTP；不支持微软推送批准或 HOTP。\n\n版本 " + BuildConfig.VERSION_NAME + " · ZXing core（Apache 2.0）")
            .setPositiveButton("知道了", null).show();
    }

    private void showStorageError() {
        new AlertDialog.Builder(this).setTitle("加密存储暂不可用")
            .setMessage("无法解密或读取已保存的账号。为保护原始数据，当前已停止添加和修改。请重启设备后重试；不要卸载应用或清除数据。")
            .setPositiveButton("知道了", null).show();
    }

    private void protectDialog(AlertDialog d) {
        if (!BuildConfig.DEBUG && d.getWindow() != null) d.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
    private LinearLayout form() { LinearLayout layout = column(); layout.setPadding(dp(24),dp(12),dp(24),dp(18)); layout.setSaveEnabled(false); return layout; }
    private ScrollView wrap(LinearLayout form) { ScrollView scroll = new ScrollView(this); scroll.addView(form); return scroll; }
    private EditText field(LinearLayout parent, String label, String value, boolean password) {
        TextView heading = text(label,12,MUTED); parent.addView(heading,margins(-1,-2,0,12,0,4));
        EditText field = new EditText(this); field.setSingleLine(true); field.setTextSize(15); field.setTextColor(TEXT);
        field.setContentDescription(label);
        field.setHintTextColor(MUTED); field.setText(value); field.setSaveEnabled(false);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        field.setInputType(InputType.TYPE_CLASS_TEXT | (password ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_FLAG_CAP_SENTENCES));
        field.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        field.setPadding(dp(12),dp(8),dp(12),dp(8)); field.setBackground(shape(PANEL,8,BORDER));
        parent.addView(field,margins(-1,dp(48),0,0,0,8)); return field;
    }
    private Spinner spinner(String[] choices) {
        Spinner spinner = new Spinner(this); ArrayAdapter<String> adapter = new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,choices);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item); spinner.setAdapter(adapter); return spinner;
    }
    private LinearLayout column() { LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); return layout; }
    private LinearLayout row() { LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.HORIZONTAL); layout.setGravity(Gravity.CENTER_VERTICAL); return layout; }
    private TextView text(String value, int size, int color) { TextView view = new TextView(this); view.setText(value); view.setTextSize(size); view.setTextColor(color); return view; }
    private Button button(String label, boolean primary) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTextSize(14); b.setTextColor(primary ? Color.WHITE : ACCENT);
        b.setTypeface(Typeface.DEFAULT, Typeface.BOLD); b.setMinWidth(0); b.setMinimumWidth(0); b.setMinHeight(0); b.setMinimumHeight(0);
        b.setPadding(dp(8),0,dp(8),0); b.setStateListAnimator(null); b.setBackground(shape(primary ? ACCENT : PANEL,12,primary ? 0 : BORDER)); return b;
    }
    private GradientDrawable shape(int color, int radius, int stroke) { GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(radius)); if(stroke!=0)d.setStroke(dp(1),stroke); return d; }
    private LinearLayout.LayoutParams margins(int w,int h,int l,int t,int r,int b) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w,h); p.setMargins(dp(l),dp(t),dp(r),dp(b)); return p; }
    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private void toast(String message) { Toast.makeText(this,message,Toast.LENGTH_LONG).show(); }
}
