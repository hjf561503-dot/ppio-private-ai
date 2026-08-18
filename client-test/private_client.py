import argparse
import base64
import hashlib
import http.client
import json
import secrets
import ssl
import time
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(b): return base64.b64encode(b).decode('ascii')
def b64d(s): return base64.b64decode(s.encode('ascii'))

def canonical(method, path, timestamp, nonce, body):
    return '\n'.join([method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest()]).encode()

class PinnedHTTPS:
    def __init__(self, base_url, fingerprint_hex):
        u = urlparse(base_url)
        if u.scheme != 'https':
            raise ValueError('HTTPS required')
        self.host = u.hostname
        self.port = u.port or 443
        self.prefix = u.path.rstrip('/')
        self.expected = fingerprint_hex.lower().replace(':', '')

    def request(self, method, path, body, headers):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(self.host, self.port, context=ctx, timeout=300)
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(der).hexdigest()
        if not secrets.compare_digest(actual, self.expected):
            conn.close()
            raise RuntimeError(f'TLS certificate pin mismatch: got {actual}')
        conn.request(method, self.prefix + path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
        status = r.status
        conn.close()
        return status, data


def signed_headers(priv, device_id, method, path, body):
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    sig = priv.sign(canonical(method, path, ts, nonce, body), ec.ECDSA(hashes.SHA256()))
    return {
        'content-type': 'application/json',
        'x-device-id': device_id,
        'x-timestamp': ts,
        'x-nonce': nonce,
        'x-signature': b64e(sig),
    }


def derive_key(shared, session_id, device_id):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(session_id.encode('ascii')).digest(),
        info=('ppio-private-ai-v1:' + device_id).encode(),
    ).derive(shared)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', required=True, help='e.g. https://host:8443')
    ap.add_argument('--pin', required=True, help='TLS_CERT_SHA256 printed by server')
    ap.add_argument('--key', default='test-device-private.pem')
    ap.add_argument('--device-id', default='tablet-main')
    ap.add_argument('--prompt', default='你好，请用中文简短介绍你自己。')
    ap.add_argument('--model', default='TrevorJS/gemma-4-26B-A4B-it-uncensored')
    args = ap.parse_args()

    priv = serialization.load_pem_private_key(open(args.key, 'rb').read(), password=None)
    http = PinnedHTTPS(args.url, args.pin)

    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    open_body = json.dumps({'client_ephemeral_x25519': b64e(eph_pub)}, separators=(',', ':')).encode()
    status, data = http.request('POST', '/session/open', open_body,
                                signed_headers(priv, args.device_id, 'POST', '/session/open', open_body))
    if status != 200:
        raise RuntimeError(f'session open failed {status}: {data[:500]!r}')
    opened = json.loads(data)
    session_id = opened['session_id']
    server_pub = x25519.X25519PublicKey.from_public_bytes(b64d(opened['server_ephemeral_x25519']))
    key = derive_key(eph_priv.exchange(server_pub), session_id, args.device_id)

    inner = json.dumps({
        'model': args.model,
        'messages': [{'role': 'user', 'content': args.prompt}],
        'max_tokens': 1200,
        'stream': False,
    }, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    req_nonce = secrets.token_bytes(12)
    aad = ('chat:' + session_id + ':' + args.device_id).encode()
    cipher = AESGCM(key).encrypt(req_nonce, inner, aad)
    outer = json.dumps({'session_id': session_id, 'nonce': b64e(req_nonce), 'ciphertext': b64e(cipher)}, separators=(',', ':')).encode()
    status, data = http.request('POST', '/v1/chat/completions', outer,
                                signed_headers(priv, args.device_id, 'POST', '/v1/chat/completions', outer))
    if status != 200:
        raise RuntimeError(f'chat failed {status}: {data[:500]!r}')
    env = json.loads(data)
    resp_nonce = b64d(env['nonce'])
    resp_cipher = b64d(env['ciphertext'])
    resp_aad = ('response:' + session_id + ':' + args.device_id).encode()
    plaintext = AESGCM(key).decrypt(resp_nonce, resp_cipher, resp_aad)
    print(plaintext.decode('utf-8'))

if __name__ == '__main__':
    main()
