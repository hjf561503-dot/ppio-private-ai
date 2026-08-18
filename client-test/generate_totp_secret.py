import secrets, base64
raw = secrets.token_bytes(20)
secret = base64.b32encode(raw).decode('ascii').rstrip('=')
print('TOTP Base32 secret (store offline; do NOT put into PPIO environment variables):')
print(secret)
print('\nAdd it manually to your Authenticator, then provision it into server RAM with set_admin_totp.sh.')
