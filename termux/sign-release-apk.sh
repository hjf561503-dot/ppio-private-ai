#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
umask 077

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/to/app-release-unsigned.apk" >&2
  exit 2
fi

INPUT="$1"
KEY_DIR="$HOME/.ppio-private-ai/signing"
KEYSTORE="$KEY_DIR/ppio-private-ai-release.p12"
ALIAS="ppio-private-ai-release"

command -v apksigner >/dev/null 2>&1 || {
  echo "apksigner not found. Install first: pkg update && pkg install apksigner" >&2
  exit 127
}

[ -f "$INPUT" ] || { echo "Input APK not found: $INPUT" >&2; exit 1; }
[ -f "$KEYSTORE" ] || { echo "Release keystore not found: $KEYSTORE" >&2; exit 1; }

ABS_INPUT="$(cd "$(dirname "$INPUT")" && pwd)/$(basename "$INPUT")"
OUT_DIR="$(dirname "$ABS_INPUT")"
OUTPUT="$OUT_DIR/ppio-private-ai-release-signed.apk"

printf "Keystore password: "
IFS= read -r -s KS_PASS
echo
export KS_PASS

rm -f "$OUTPUT" "$OUTPUT.idsig"

apksigner sign \
  --ks "$KEYSTORE" \
  --ks-type PKCS12 \
  --ks-key-alias "$ALIAS" \
  --ks-pass env:KS_PASS \
  --key-pass env:KS_PASS \
  --out "$OUTPUT" \
  "$ABS_INPUT"

unset KS_PASS

apksigner verify --verbose --print-certs "$OUTPUT"
sha256sum "$OUTPUT" | tee "$OUTPUT.sha256"

chmod 600 "$OUTPUT" "$OUTPUT.sha256"

echo
echo "Signed APK: $OUTPUT"
echo "SHA-256 file: $OUTPUT.sha256"
echo "Keep the release keystore and its password private and backed up separately."
