import asyncio
import base64
import hashlib
import hmac
import json
import os
import resource
import secrets
import time
from dataclasses import dataclass
from typing import Dict

import httpx
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, HTTPException, Request, Response

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)

APP_NAME = "PPIO H20 Private AI Gateway"
VLLM_UDS = os.environ.get("VLLM_UDS", "/dev/shm/private-ai/vllm.sock")
VLLM_KEY_FILE = os.environ.get("VLLM_KEY_FILE", "/dev/shm/private-ai/vllm.key")
TRUSTED_DEVICES_FILE = os.environ.get("TRUSTED_DEVICES_FILE", "/etc/private-ai/trusted_devices.json")
TRUSTED_DEVICES_JSON_B64 = os.environ.get("TRUSTED_DEVICES_JSON_B64", "")
ADMIN_TOTP_FILE = os.environ.get("ADMIN_TOTP_FILE", "/dev/shm/private-ai/admin_totp.secret")
MAX_CLOCK_SKEW = int(os.environ.get("MAX_CLOCK_SKEW", "90"))
SESSION_TTL = int(os.environ.get("SESSION_TTL", "1800"))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(8 * 1024 * 1024)))
MAX_FAILURES_PER_MIN = int(os.environ.get("MAX_FAILURES_PER_MIN", "12"))
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "8"))

app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None, openapi_url=None)

@dataclass
class Session:
    device_id: str
    key: bytes
    expires_at: float

sessions: Dict[str, Session] = {}
seen_nonces: Dict[str, float] = {}
failures: Dict[str, list] = {}
locked_down = False
state_lock = asyncio.Lock()


def _load_trusted_devices():
    if TRUSTED_DEVICES_JSON_B64:
        try:
            raw = json.loads(base64.b64decode(TRUSTED_DEVICES_JSON_B64).decode("utf-8"))
        except Exception as e:
            raise RuntimeError("Invalid TRUSTED_DEVICES_JSON_B64") from e
    else:
        try:
            with open(TRUSTED_DEVICES_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            raise RuntimeError("No trusted devices configured. Set TRUSTED_DEVICES_JSON_B64 or mount trusted_devices.json")
    devices = {}
    for device_id, item in raw.items():
        if not item.get("enabled", True):
            continue
        pem = item["public_key_pem"].encode("utf-8")
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise RuntimeError(f"Device {device_id} must use ECDSA P-256")
        devices[device_id] = key
    if not devices:
        raise RuntimeError("No enabled trusted device")
    return devices

TRUSTED_DEVICES = _load_trusted_devices()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return "\n".join([method.upper(), path, timestamp, nonce, _sha256(body)]).encode("utf-8")


async def _prune_state():
    now = time.time()
    async with state_lock:
        for sid in [k for k, v in sessions.items() if v.expires_at <= now]:
            sess = sessions.pop(sid)
            del sess
        for nonce in [k for k, exp in seen_nonces.items() if exp <= now]:
            seen_nonces.pop(nonce, None)
        for k in list(failures):
            failures[k] = [t for t in failures[k] if now - t < 60]
            if not failures[k]:
                failures.pop(k, None)


async def _record_failure(bucket: str):
    now = time.time()
    async with state_lock:
        arr = failures.setdefault(bucket, [])
        arr[:] = [t for t in arr if now - t < 60]
        arr.append(now)
        n = len(arr)
    await asyncio.sleep(min(0.15 * max(1, n), 2.0))
    if n > MAX_FAILURES_PER_MIN:
        raise HTTPException(status_code=429, detail="rate limited")


async def _verify_signed_request(request: Request, body: bytes):
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="body too large")

    device_id = request.headers.get("x-device-id", "")
    timestamp = request.headers.get("x-timestamp", "")
    nonce = request.headers.get("x-nonce", "")
    signature_b64 = request.headers.get("x-signature", "")

    key = TRUSTED_DEVICES.get(device_id)
    if key is None:
        await _record_failure("unknown-device")
        raise HTTPException(status_code=401, detail="unauthorized")

    try:
        ts = int(timestamp)
    except ValueError:
        await _record_failure(device_id)
        raise HTTPException(status_code=401, detail="unauthorized")

    now = int(time.time())
    if abs(now - ts) > MAX_CLOCK_SKEW:
        await _record_failure(device_id)
        raise HTTPException(status_code=401, detail="stale request")

    if len(nonce) < 24 or len(nonce) > 128:
        await _record_failure(device_id)
        raise HTTPException(status_code=401, detail="bad nonce")

    await _prune_state()
    async with state_lock:
        replay = nonce in seen_nonces
    if replay:
        await _record_failure(device_id)
        raise HTTPException(status_code=409, detail="replay blocked")

    canonical = _canonical(request.method, request.url.path, timestamp, nonce, body)
    try:
        key.verify(_b64d(signature_b64), canonical, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        await _record_failure(device_id)
        raise HTTPException(status_code=401, detail="unauthorized")

    async with state_lock:
        seen_nonces[nonce] = time.time() + MAX_CLOCK_SKEW * 2
    return device_id


def _derive_session_key(shared_secret: bytes, session_id: str, device_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(session_id.encode("ascii")).digest(),
        info=("ppio-private-ai-v1:" + device_id).encode("utf-8"),
    ).derive(shared_secret)


def _read_vllm_key() -> str:
    with open(VLLM_KEY_FILE, "r", encoding="ascii") as f:
        return f.read().strip()


def _totp_code(secret_b32: str, counter: int, digits: int = 6) -> str:
    import struct
    normalized = ''.join(secret_b32.strip().split()).upper()
    padding = '=' * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24) | ((digest[offset+1] & 0xFF) << 16) | ((digest[offset+2] & 0xFF) << 8) | (digest[offset+3] & 0xFF)
    return str(binary % (10 ** digits)).zfill(digits)


def _verify_totp(secret_b32: str, code: str, window: int = 1, step: int = 30) -> bool:
    if not (code.isdigit() and len(code) == 6):
        return False
    current = int(time.time()) // step
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_totp_code(secret_b32, current + delta), code):
            return True
    return False


def _read_totp_secret() -> str | None:
    try:
        with open(ADMIN_TOTP_FILE, "r", encoding="ascii") as f:
            secret = f.read().strip()
            return secret or None
    except FileNotFoundError:
        return None


@app.get("/healthz")
async def healthz():
    return {"ok": not locked_down, "mode": "locked" if locked_down else "ready"}


@app.post("/session/open")
async def session_open(request: Request):
    global locked_down
    if locked_down:
        raise HTTPException(status_code=423, detail="locked")
    body = await request.body()
    device_id = await _verify_signed_request(request, body)
    try:
        payload = json.loads(body)
        client_pub_raw = _b64d(payload["client_ephemeral_x25519"])
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_raw)
    except Exception:
        raise HTTPException(status_code=400, detail="bad handshake")

    server_priv = x25519.X25519PrivateKey.generate()
    server_pub_raw = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared = server_priv.exchange(client_pub)
    session_id = secrets.token_urlsafe(32)
    key = _derive_session_key(shared, session_id, device_id)
    expires = time.time() + SESSION_TTL
    async with state_lock:
        if len(sessions) >= MAX_SESSIONS:
            oldest = min(sessions, key=lambda sid: sessions[sid].expires_at)
            sessions.pop(oldest, None)
        sessions[session_id] = Session(device_id=device_id, key=key, expires_at=expires)
    del server_priv, shared
    return {
        "session_id": session_id,
        "server_ephemeral_x25519": _b64e(server_pub_raw),
        "expires_unix": int(expires),
        "aead": "AES-256-GCM",
        "kdf": "HKDF-SHA256",
    }


@app.post("/v1/chat/completions")
async def chat(request: Request):
    global locked_down
    if locked_down:
        raise HTTPException(status_code=423, detail="locked")
    outer = await request.body()
    device_id = await _verify_signed_request(request, outer)

    try:
        envelope = json.loads(outer)
        session_id = envelope["session_id"]
        nonce = _b64d(envelope["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])
    except Exception:
        raise HTTPException(status_code=400, detail="bad envelope")

    async with state_lock:
        sess = sessions.get(session_id)
    if sess is None or sess.expires_at <= time.time() or not hmac.compare_digest(sess.device_id, device_id):
        raise HTTPException(status_code=401, detail="invalid session")
    if len(nonce) != 12:
        raise HTTPException(status_code=400, detail="bad nonce")

    aad = ("chat:" + session_id + ":" + device_id).encode("utf-8")
    try:
        plaintext = AESGCM(sess.key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        await _record_failure(device_id)
        raise HTTPException(status_code=401, detail="decryption failed")

    try:
        vllm_key = _read_vllm_key()
        transport = httpx.AsyncHTTPTransport(uds=VLLM_UDS)
        async with httpx.AsyncClient(transport=transport, base_url="http://vllm", timeout=httpx.Timeout(300.0, connect=5.0)) as client:
            r = await client.post(
                "/v1/chat/completions",
                content=plaintext,
                headers={
                    "content-type": "application/json",
                    "authorization": "Bearer " + vllm_key,
                },
            )
        response_plain = r.content
        status_code = r.status_code
    finally:
        if plaintext:
            tmp = bytearray(plaintext)
            for i in range(len(tmp)):
                tmp[i] = 0
            del tmp
        plaintext = b""

    resp_nonce = secrets.token_bytes(12)
    resp_aad = ("response:" + session_id + ":" + device_id).encode("utf-8")
    resp_cipher = AESGCM(sess.key).encrypt(resp_nonce, response_plain, resp_aad)
    if response_plain:
        tmp2 = bytearray(response_plain)
        for i in range(len(tmp2)):
            tmp2[i] = 0
        del tmp2
    response_plain = b""
    return Response(
        content=json.dumps({
            "session_id": session_id,
            "nonce": _b64e(resp_nonce),
            "ciphertext": _b64e(resp_cipher),
            "upstream_status": status_code,
        }, separators=(",", ":")),
        media_type="application/json",
        status_code=200,
    )


@app.post("/admin/lockdown")
async def admin_lockdown(request: Request):
    global locked_down
    body = await request.body()
    await _verify_signed_request(request, body)
    totp_secret = _read_totp_secret()
    if not totp_secret:
        raise HTTPException(status_code=503, detail="admin TOTP not provisioned")
    code = request.headers.get("x-admin-totp", "")
    if not _verify_totp(totp_secret, code, window=1):
        await _record_failure("admin-totp")
        raise HTTPException(status_code=401, detail="unauthorized")

    async with state_lock:
        locked_down = True
        sessions.clear()
        seen_nonces.clear()
    try:
        with open(VLLM_KEY_FILE, "wb") as f:
            f.write(secrets.token_bytes(96))
            f.flush()
            os.fsync(f.fileno())
        os.unlink(VLLM_KEY_FILE)
    except FileNotFoundError:
        pass
    return {"locked": True, "restart_required": True}
