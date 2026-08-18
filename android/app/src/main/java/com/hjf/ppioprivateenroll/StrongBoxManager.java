package com.hjf.ppioprivateenroll;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Locale;

public final class StrongBoxManager {
    public static final String ALIAS = "ppio_private_ai_device_identity_v1";
    private static final String PREFS = "enrollment_public_state";
    private static final String PREF_CHALLENGE = "attestation_challenge_b64";

    private final Context context;

    public StrongBoxManager(Context context) {
        this.context = context.getApplicationContext();
    }

    public boolean hasStrongBoxFeature() {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    public synchronized void createIfMissing() throws Exception {
        KeyStore ks = keyStore();
        if (ks.containsAlias(ALIAS)) return;
        if (!hasStrongBoxFeature()) {
            throw new IllegalStateException("该设备未声明 StrongBox KeyStore；按安全策略拒绝降级到普通 TEE。\n");
        }

        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);

        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .setIsStrongBoxBacked(true)
                .setUserAuthenticationRequired(true)
                .setUnlockedDeviceRequired(true);

        if (Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        }

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(b.build());
            kpg.generateKeyPair();
        } catch (StrongBoxUnavailableException e) {
            throw new IllegalStateException(
                    "系统声明支持 StrongBox，但当前无法按要求生成 StrongBox ECDSA 密钥；已拒绝自动降级。", e);
        }

        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(PREF_CHALLENGE, Base64.encodeToString(challenge, Base64.NO_WRAP))
                .apply();
    }

    public synchronized PrivateKey privateKey() throws Exception {
        KeyStore ks = keyStore();
        java.security.Key key = ks.getKey(ALIAS, null);
        if (!(key instanceof PrivateKey)) throw new IllegalStateException("设备身份私钥不存在");
        return (PrivateKey) key;
    }

    public synchronized PublicKey publicKey() throws Exception {
        Certificate cert = keyStore().getCertificate(ALIAS);
        if (cert == null) throw new IllegalStateException("设备身份证书不存在");
        return cert.getPublicKey();
    }

    public synchronized int securityLevel() throws Exception {
        PrivateKey key = privateKey();
        KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo info = kf.getKeySpec(key, KeyInfo.class);
        if (Build.VERSION.SDK_INT >= 31) return info.getSecurityLevel();
        return info.isInsideSecureHardware()
                ? KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
                : KeyProperties.SECURITY_LEVEL_SOFTWARE;
    }

    public String securityLevelName() throws Exception {
        int level = securityLevel();
        if (Build.VERSION.SDK_INT >= 31 && level == KeyProperties.SECURITY_LEVEL_STRONGBOX) return "STRONGBOX";
        if (Build.VERSION.SDK_INT >= 31 && level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) return "TRUSTED_ENVIRONMENT";
        if (level == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE) return "UNKNOWN_SECURE";
        if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE) return "SOFTWARE";
        return "UNKNOWN(" + level + ")";
    }

    public synchronized String deviceId() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey().getEncoded());
        StringBuilder sb = new StringBuilder("sbx-");
        for (int i = 0; i < 16; i++) sb.append(String.format(Locale.US, "%02x", digest[i]));
        return sb.toString();
    }

    public synchronized String registrationBundleJson() throws Exception {
        createIfMissing();
        JSONObject out = new JSONObject();
        out.put("schema", "ppio-private-ai-strongbox-enrollment-v1");
        out.put("device_id", deviceId());
        out.put("public_key_pem", toPem(publicKey().getEncoded(), "PUBLIC KEY"));
        out.put("strongbox_feature", hasStrongBoxFeature());
        out.put("security_level", securityLevelName());
        out.put("auth_per_use", true);
        out.put("private_key_exportable", false);
        out.put("created_from_package", context.getPackageName());
        out.put("attestation_challenge_b64", context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(PREF_CHALLENGE, ""));

        JSONArray chain = new JSONArray();
        Certificate[] certs = keyStore().getCertificateChain(ALIAS);
        if (certs == null || certs.length == 0) throw new IllegalStateException("Attestation certificate chain missing");
        for (Certificate cert : certs) {
            chain.put(Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
        }
        out.put("attestation_cert_chain_der_b64", chain);
        return out.toString(2);
    }

    public synchronized void resetIdentity() throws Exception {
        KeyStore ks = keyStore();
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply();
    }

    private KeyStore keyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    private static String toPem(byte[] der, String type) {
        String b64 = Base64.encodeToString(der, Base64.NO_WRAP);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }
}
