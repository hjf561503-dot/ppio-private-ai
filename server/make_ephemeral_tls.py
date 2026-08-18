import datetime
import hashlib
import ipaddress
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = os.environ.get("TLS_DIR", "/dev/shm/private-ai/tls")
os.makedirs(out, mode=0o700, exist_ok=True)
key_path = os.path.join(out, "server.key")
cert_path = os.path.join(out, "server.crt")

key = ec.generate_private_key(ec.SECP256R1())
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ppio-private-ai-ephemeral")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=1))
    .not_valid_after(now + datetime.timedelta(days=7))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("ppio-private-ai"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False
    )
    .sign(key, hashes.SHA256())
)
with open(key_path, "wb") as f:
    os.chmod(key_path, 0o600)
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
with open(cert_path, "wb") as f:
    os.chmod(cert_path, 0o644)
    der = cert.public_bytes(serialization.Encoding.DER)
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("TLS_CERT_SHA256=" + hashlib.sha256(der).hexdigest())
