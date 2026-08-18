package privateai.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Production device identity skeleton.
 * Private key is generated inside Android Keystore/StrongBox and is never exported.
 * This code intentionally fails closed if StrongBox is unavailable.
 */
object StrongBoxIdentity {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "private_ai_device_identity_v1"

    fun ensureKey() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) return

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                300,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            .setIsStrongBoxBacked(true)
            .build()
        try {
            generator.initialize(spec)
            generator.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            throw IllegalStateException("StrongBox is required by policy", e)
        }
    }

    fun publicKeyPem(): String {
        ensureKey()
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val cert = ks.getCertificate(ALIAS)
        val b64 = android.util.Base64.encodeToString(cert.publicKey.encoded, android.util.Base64.NO_WRAP)
        return "-----BEGIN PUBLIC KEY-----\n" +
            b64.chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----\n"
    }

    fun sign(canonicalRequest: ByteArray): ByteArray {
        ensureKey()
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = ks.getKey(ALIAS, null) as java.security.PrivateKey
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(canonicalRequest)
            sign()
        }
    }
}
