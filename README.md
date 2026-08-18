# PPIO H20 Private AI Gateway v2

A privacy-hardened gateway for a self-hosted vLLM model on a normal PPIO H20 GPU instance. **No web-search integration is included.**

## Security boundary

This project is designed so that ordinary disk snapshots, container images, application logs, and captured network traffic do not need to contain readable chat history. It cannot protect active CPU/GPU plaintext from a malicious cloud host/hypervisor because H20 is not a Confidential Computing GPU.

## Runtime architecture

```text
Android device identity (production: StrongBox P-256)
       │
       │ TLS certificate pinning
       │ + signed requests
       │ + X25519/HKDF/AES-256-GCM application encryption
       ▼
TLS gateway :8443
       │
       │ Unix-domain socket in /dev/shm only
       ▼
vLLM (no TCP listener, no public port)
       ▼
H20 96 GB
```

Privacy hardening includes:

- vLLM is reachable only via a RAM-backed Unix-domain socket.
- The public listener is the gateway only.
- TLS key/certificate are generated per boot in `/dev/shm`.
- Device requests are signed with ECDSA P-256 and include timestamp + nonce replay protection.
- Each session uses ephemeral X25519 + HKDF-SHA256 + AES-256-GCM inside TLS.
- vLLM's internal API credential is random per boot and RAM-only.
- Request/output/access/stat logging is explicitly disabled where supported by the installed vLLM version.
- vLLM and gateway stdout/stderr are kept out of persistent storage where possible.
- No conversation database exists server-side.
- Core dumps are disabled.
- The container runs as vLLM's built-in non-root UID 2000.
- Emergency lockdown invalidates sessions and the internal RAM-only credential; it does not expose a remote disk-wipe DoS primitive.
- The vLLM base image is pinned to a release tag instead of `latest`.
- The Hugging Face model revision is pinned to an immutable commit by default.

See `SECURITY_MODEL.md` for the threat model.

## GHCR build

Pushing `server/**` to `main` triggers `.github/workflows/build-image.yml` and publishes:

```text
ghcr.io/<owner>/ppio-private-ai:latest
ghcr.io/<owner>/ppio-private-ai:<git-commit-sha>
```

For production, prefer the immutable commit-SHA tag instead of `latest`.

The workflow uses the repository-scoped `GITHUB_TOKEN`; no PAT is required in repository secrets.

## PPIO template

Recommended template fields:

```text
Template name: ppio-private-ai-h20
Minimum CUDA: 12.4
Container image: ghcr.io/<owner>/ppio-private-ai:<immutable-build-commit-sha>
Container command: blank
Entrypoint: blank
System disk: 130 GB
Public HTTP ports: blank
Public TCP ports: 8443
```

Environment variables:

```text
MODEL=TrevorJS/gemma-4-26B-A4B-it-uncensored
MODEL_REVISION=fc582b971b5b6f7738d311d7ea2b1b7b446ff0a1
MAX_MODEL_LEN=50000
GPU_MEMORY_UTILIZATION=0.90
GATEWAY_PORT=8443
TRUSTED_DEVICES_JSON_B64=<public device configuration only>
```

Do not put private device keys, TOTP secrets, TLS private keys, or chat records in GitHub or PPIO environment variables.

## First-device provisioning

The production Android enrollment app creates a P-256 identity in Android StrongBox, requires per-use authentication, and exports only the public enrollment bundle. The server should receive only the minimized device ID + public key configuration through `TRUSTED_DEVICES_JSON_B64`; the StrongBox private key never leaves the Android device.

The per-boot TLS fingerprint is printed as:

```text
[SECURITY] TLS_CERT_SHA256=...
```

Verify it out-of-band before sending private chat data.
