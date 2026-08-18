# PPIO H20 Private AI Gateway

A privacy-hardened gateway for a self-hosted vLLM model on a normal PPIO H20 GPU instance. **No web-search integration is included.**

## Security boundary

The project is designed so ordinary disk snapshots, application logs and captured network traffic do not need to contain readable chat history. It cannot protect active CPU/GPU plaintext from a malicious cloud host/hypervisor because an ordinary H20 instance is not Confidential Computing.

## Runtime architecture

```text
Android StrongBox P-256 device identity
       │
       │ TLS certificate pinning
       │ + authenticated session establishment
       │ + X25519/HKDF/AES-256-GCM application encryption
       ▼
TLS gateway :8443
       │
       │ Unix-domain socket in /dev/shm
       ▼
vLLM
       ▼
H20 96 GB
```

Current hardening includes:

- vLLM's OpenAI API is reachable only through a RAM-backed Unix-domain socket.
- The public listener is the gateway only.
- TLS key/certificate are generated per boot in `/dev/shm`.
- Device enrollment uses an Android StrongBox-backed, non-exportable P-256 key.
- Session establishment is ECDSA-signed and has timestamp + nonce replay protection.
- Each session uses ephemeral X25519 + HKDF-SHA256 + AES-256-GCM inside TLS.
- vLLM's internal API credential is random per boot and RAM-only.
- Request/output/access/stat logging is disabled where supported by the pinned vLLM version.
- vLLM/Hugging Face telemetry is explicitly opted out.
- HTTP media redirects are disabled; production must reject or explicitly allowlist remote media before enabling multimodal URL inputs.
- Core dumps and Python bytecode persistence are disabled.
- The serving container runs as a non-root user after image setup.
- No server-side conversation database is implemented.

See `SECURITY_MODEL.md` for the exact threat model and remaining limitations.

## Important: current Android state

The release-signed Android APK currently in this repository is a **StrongBox enrollment and signature-validation app**. It deliberately has no `INTERNET` permission. It establishes the hardware-backed device identity but it is **not yet the final chat client**.

The final chat client must be shipped as an update using the same `applicationId` and the same offline-held release signing key so the existing StrongBox identity can be retained.

## Pinned model/runtime defaults

```text
vLLM image: vllm/vllm-openai:v0.26.0
MODEL=TrevorJS/gemma-4-26B-A4B-it-uncensored
MODEL_REVISION=fc582b971b5b6f7738d311d7ea2b1b7b446ff0a1
MAX_MODEL_LEN=50000
GPU_MEMORY_UTILIZATION=0.90
```

The Docker tag is version-pinned, but for maximum supply-chain reproducibility a future release should pin the base image by immutable OCI digest and pin GitHub Actions by full commit SHA.

## GHCR build

Pushing `server/**` to `main` triggers `.github/workflows/build-image.yml` and publishes both `latest` and a commit-SHA tag:

```text
ghcr.io/<owner>/ppio-private-ai:latest
ghcr.io/<owner>/ppio-private-ai:<full-git-sha>
```

Use the full commit-SHA image tag for production deployment rather than `latest`.

## PPIO template target

```text
Template name: ppio-private-ai-h20
Minimum CUDA: 12.4
Container image: ghcr.io/<owner>/ppio-private-ai:<audited-server-commit-sha>
Container command: blank
Entrypoint: blank
System disk: 130 GB
Public HTTP ports: blank
Public TCP ports: 8443
```

Environment variables currently used by the server:

```text
MODEL=TrevorJS/gemma-4-26B-A4B-it-uncensored
MODEL_REVISION=fc582b971b5b6f7738d311d7ea2b1b7b446ff0a1
MAX_MODEL_LEN=50000
GPU_MEMORY_UTILIZATION=0.90
GATEWAY_PORT=8443
TRUSTED_DEVICES_JSON_B64=<public device configuration only>
```

Do not put private device keys, APK signing keys, TOTP secrets, TLS private keys or chat records in GitHub or PPIO environment variables.

## Deployment gate

A green GHCR build proves the image built and was pushed; it does **not** prove end-to-end security or that the Android client can chat. Do not start a paid H20 production instance until the final Android network client, session protocol, emergency-lock behavior, and end-to-end tests are complete.
