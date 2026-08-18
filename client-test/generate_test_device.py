import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key()
with open('test-device-private.pem', 'wb') as f:
    os.chmod('test-device-private.pem', 0o600)
    f.write(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
with open('trusted_devices.json', 'w', encoding='utf-8') as f:
    json.dump({'tablet-main': {'enabled': True, 'public_key_pem': pub_pem}}, f, indent=2)
print('Created test-device-private.pem (TEST ONLY; production key should live in Android StrongBox)')
print('Created trusted_devices.json for the server')
