package com.hjf.ppioprivateenroll;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Typeface;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.SecureRandom;
import java.util.concurrent.Executor;

public final class MainActivity extends Activity {
    private StrongBoxManager strongBox;
    private TextView status;
    private String currentBundle = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        strongBox = new StrongBoxManager(this);
        setContentView(buildUi());
        renderInitialStatus();
    }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("PPIO 私有 AI · StrongBox 设备绑定");
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView note = new TextView(this);
        note.setText("安全策略：只接受 StrongBox，不自动降级到普通 TEE。此 APK 没有 INTERNET 权限，无法把设备身份或注册包上传到网络。私钥不可导出，并要求每次使用私钥时进行强生物识别/设备凭据授权。");
        note.setTextSize(15);
        note.setPadding(0, dp(10), 0, dp(14));
        root.addView(note);

        Button create = new Button(this);
        create.setText("1. 生成 / 读取 StrongBox 身份");
        create.setOnClickListener(v -> createOrLoad());
        root.addView(create);

        Button selfTest = new Button(this);
        selfTest.setText("2. 生物识别签名自检");
        selfTest.setOnClickListener(v -> biometricSelfTest());
        root.addView(selfTest);

        Button copy = new Button(this);
        copy.setText("3. 复制公开注册包");
        copy.setOnClickListener(v -> copyBundle());
        root.addView(copy);

        Button reset = new Button(this);
        reset.setText("重置本机身份（危险）");
        reset.setOnClickListener(v -> confirmReset());
        root.addView(reset);

        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextSize(13);
        status.setPadding(0, dp(16), 0, dp(24));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(status);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private void renderInitialStatus() {
        status.setText(
                "StrongBox feature: " + (strongBox.hasStrongBoxFeature() ? "YES" : "NO") + "\n" +
                "Android API: " + Build.VERSION.SDK_INT + "\n" +
                "Network permission: NONE\n\n" +
                "先点第 1 个按钮。若设备不支持 StrongBox，本应用会直接失败，不会静默降级。\n");
    }

    private void createOrLoad() {
        try {
            strongBox.createIfMissing();
            currentBundle = strongBox.registrationBundleJson();
            String level = strongBox.securityLevelName();
            if (!"STRONGBOX".equals(level) && Build.VERSION.SDK_INT >= 31) {
                throw new IllegalStateException("密钥安全级别不是 STRONGBOX，而是 " + level + "；按策略拒绝登记。\n");
            }
            status.setText(
                    "✅ StrongBox 身份已就绪\n" +
                    "Device ID: " + strongBox.deviceId() + "\n" +
                    "Security level: " + level + "\n" +
                    "Private key exportable: NO\n" +
                    "Auth per use: YES\n" +
                    "Network permission: NONE\n\n" +
                    "下面是公开注册包（可以复制；其中不含私钥）：\n\n" + currentBundle);
        } catch (Exception e) {
            currentBundle = "";
            status.setText("❌ StrongBox 身份创建/读取失败\n\n" + safeError(e));
        }
    }

    private void biometricSelfTest() {
        try {
            strongBox.createIfMissing();
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(strongBox.privateKey());
            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);

            BiometricPrompt.Builder builder = new BiometricPrompt.Builder(this)
                    .setTitle("验证设备身份")
                    .setSubtitle("授权 StrongBox 私钥完成一次本地签名自检")
                    .setConfirmationRequired(true);

            if (Build.VERSION.SDK_INT >= 30) {
                builder.setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG |
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL);
            } else {
                builder.setNegativeButton("取消", getMainExecutor(), (dialog, which) -> {});
            }

            BiometricPrompt prompt = builder.build();
            Executor executor = getMainExecutor();
            prompt.authenticate(
                    new BiometricPrompt.CryptoObject(sig),
                    new CancellationSignal(),
                    executor,
                    new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            super.onAuthenticationSucceeded(result);
                            try {
                                Signature unlocked = result.getCryptoObject() == null ? null : result.getCryptoObject().getSignature();
                                if (unlocked == null) throw new IllegalStateException("系统未返回已授权 Signature");
                                unlocked.update(challenge);
                                byte[] signature = unlocked.sign();

                                Signature verify = Signature.getInstance("SHA256withECDSA");
                                verify.initVerify(strongBox.publicKey());
                                verify.update(challenge);
                                if (!verify.verify(signature)) throw new IllegalStateException("本地签名验证失败");

                                status.setText(
                                        "✅ StrongBox + 用户认证 + ECDSA 签名自检全部通过\n" +
                                        "Device ID: " + strongBox.deviceId() + "\n" +
                                        "Security level: " + strongBox.securityLevelName() + "\n\n" +
                                        "现在可以点“复制公开注册包”。");
                            } catch (Exception e) {
                                status.setText("❌ 签名自检失败\n\n" + safeError(e));
                            }
                        }

                        @Override
                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            super.onAuthenticationError(errorCode, errString);
                            status.setText("❌ 身份验证未完成\nerror=" + errorCode + "\n" + errString);
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            super.onAuthenticationFailed();
                            Toast.makeText(MainActivity.this, "未通过验证，请重试", Toast.LENGTH_SHORT).show();
                        }
                    });
        } catch (Exception e) {
            status.setText("❌ 无法启动签名自检\n\n" + safeError(e));
        }
    }

    private void copyBundle() {
        try {
            if (currentBundle.isEmpty()) currentBundle = strongBox.registrationBundleJson();
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("PPIO StrongBox enrollment", currentBundle));
            Toast.makeText(this, "已复制公开注册包（不含私钥）", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            status.setText("❌ 无法读取注册包\n\n" + safeError(e));
        }
    }

    private void confirmReset() {
        new AlertDialog.Builder(this)
                .setTitle("确认重置设备身份？")
                .setMessage("这会永久删除本应用在 Android Keystore/StrongBox 中的设备私钥。若服务器已经绑定此 Device ID，旧身份将无法再使用。")
                .setNegativeButton("取消", null)
                .setPositiveButton("永久删除", (d, w) -> {
                    try {
                        strongBox.resetIdentity();
                        currentBundle = "";
                        renderInitialStatus();
                        Toast.makeText(this, "设备身份已删除", Toast.LENGTH_LONG).show();
                    } catch (Exception e) {
                        status.setText("❌ 删除失败\n\n" + safeError(e));
                    }
                })
                .show();
    }

    private static String safeError(Throwable t) {
        String msg = t.getMessage();
        return t.getClass().getSimpleName() + (msg == null ? "" : ": " + msg);
    }

    private int dp(int n) {
        return Math.round(n * getResources().getDisplayMetrics().density);
    }
}
