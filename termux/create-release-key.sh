#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
umask 077

KEY_DIR="$HOME/.ppio-private-ai/signing"
KEYSTORE="$KEY_DIR/ppio-private-ai-release.p12"
ALIAS="ppio-private-ai-release"

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

if [ -e "$KEYSTORE" ]; then
  echo "Refusing to overwrite existing keystore: $KEYSTORE" >&2
  echo "If this is the real release key, keep it. Losing/replacing it breaks seamless app updates." >&2
  exit 1
fi

command -v keytool >/dev/null 2>&1 || {
  echo "keytool not found. Install first: pkg update && pkg install openjdk-21 apksigner" >&2
  exit 127
}

echo "Create the long-term APK release signing key locally on this Android device."
echo "The private key will NOT be uploaded to GitHub or placed in the repository."
printf "Enter a strong ASCII password for the encrypted PKCS#12 keystore: "
IFS= read -r -s KS_PASS
echo
printf "Enter it again: "
IFS= read -r -s KS_PASS_2
echo

if [ "$KS_PASS" != "$KS_PASS_2" ]; then
  unset KS_PASS KS_PASS_2
  echo "Passwords do not match." >&2
  exit 2
fi
if [ "${#KS_PASS}" -lt 16 ]; then
  unset KS_PASS KS_PASS_2
  echo "Use at least 16 characters." >&2
  exit 2
fi
unset KS_PASS_2
export KS_PASS

keytool -genkeypair \
  -keystore "$KEYSTORE" \
  -storetype PKCS12 \
  -alias "$ALIAS" \
  -keyalg RSA \
  -keysize 4096 \
  -sigalg SHA256withRSA \
  -validity 36500 \
  -dname "CN=PPIO Private AI Release,O=Private" \
  -storepass:env KS_PASS \
  -keypass:env KS_PASS

chmod 600 "$KEYSTORE"

CERT_FILE="$KEY_DIR/release-certificate.pem"
keytool -exportcert -rfc \
  -keystore "$KEYSTORE" \
  -storetype PKCS12 \
  -alias "$ALIAS" \
  -storepass:env KS_PASS \
  -file "$CERT_FILE" >/dev/null
chmod 644 "$CERT_FILE"

FINGERPRINT_FILE="$KEY_DIR/release-certificate-sha256.txt"
keytool -list -v \
  -keystore "$KEYSTORE" \
  -storetype PKCS12 \
  -alias "$ALIAS" \
  -storepass:env KS_PASS \
  | awk '/SHA256:/{print; exit}' | tee "$FINGERPRINT_FILE"
chmod 644 "$FINGERPRINT_FILE"

unset KS_PASS

echo
echo "Created: $KEYSTORE"
echo "Public certificate: $CERT_FILE"
echo "Fingerprint: $FINGERPRINT_FILE"
echo
echo "IMPORTANT: make at least TWO encrypted backups of the .p12 file, kept separately."
echo "Do not upload the .p12 or its password to GitHub, PPIO, chat, cloud notes, or the public repository."
