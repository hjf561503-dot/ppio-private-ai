#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
RAMDIR=/dev/shm/private-ai
mkdir -p "$RAMDIR"
read -r -s -p 'Paste Authenticator TOTP secret (Base32, input hidden): ' SECRET
echo
printf '%s' "$SECRET" > "$RAMDIR/admin_totp.secret"
unset SECRET
chmod 600 "$RAMDIR/admin_totp.secret"
echo 'Admin TOTP provisioned in RAM only; it disappears on restart.'
