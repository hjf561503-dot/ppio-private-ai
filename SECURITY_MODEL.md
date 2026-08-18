# Security model

## Goal

Minimize readable chat plaintext outside volatile process/GPU memory on a normal PPIO H20 instance, while keeping the inference model self-hosted.

## Hard boundary

H20 is not NVIDIA Confidential Computing. A cloud provider or attacker with sufficient host/hypervisor control can potentially inspect plaintext while inference is active. This design therefore protects **data at rest, ordinary logs, network transit, replay/authentication, and accidental disclosure**, not a malicious hypervisor.

Python, HTTP libraries, tokenizers and GPU runtimes may create temporary in-memory copies. Clearing references/buffers is only best-effort and is **not** a cryptographic guarantee that plaintext has been erased from CPU RAM or GPU VRAM while the instance is running.

## Trust and data-flow rules

1. The Android device is the long-term identity root. Production identity uses a non-exportable P-256 key in Android StrongBox.
2. The server's public entry point is TLS port 8443 only.
3. vLLM has no public or loopback TCP API port; its OpenAI API uses a Unix-domain socket located in `/dev/shm`.
4. TLS identity is per-boot and RAM-only. The client must pin the certificate fingerprint out-of-band before sending private data.
5. Session establishment is device-signed and includes timestamp, nonce and request-body hash. The current prototype also signs chat requests; the production chat protocol should move to authenticated per-session sequence numbers so StrongBox authentication is not required for every message.
6. Session confidentiality adds X25519 + HKDF-SHA256 + AES-256-GCM inside TLS.
7. No chat database is implemented on the server.
8. Prompt/output/access/stat logging is explicitly disabled where supported by the pinned vLLM version.
9. vLLM and Hugging Face telemetry are explicitly opted out through environment variables.
10. Core dumps and Python bytecode persistence are disabled.
11. The container runs as a non-root user after image setup.
12. Admin lockdown requires device authentication plus TOTP. A production lockdown path should also terminate the vLLM process so its KV cache/VRAM allocations are released; deletion of cloud-provider copies cannot be guaranteed on an ordinary H20 instance.
13. A failed/unknown login never destroys storage; this prevents attackers from turning authentication failure into a remote self-destruct denial-of-service primitive.
14. Remote media URL fetching must remain disabled/rejected until a deliberate media allowlist is implemented. vLLM HTTP media redirects are disabled by default in this image.

## Intentionally not persisted by this application

- Prompt bodies
- Model response bodies
- Conversation history/database
- TLS private key
- vLLM API credential
- Session encryption keys
- Admin TOTP secret

Model weights and compilation/model caches are persistent and are not chat records.

## Still observable to the cloud/network layer

- Account identity and instance metadata
- GPU/CPU/storage usage
- Source/destination IPs, timing and traffic volume
- Open public TCP port
- Plaintext that exists in CPU RAM/GPU VRAM during active inference if the host/hypervisor is malicious

## Current deployment readiness

The StrongBox enrollment APK is complete enough to establish a hardware-backed public identity. It intentionally has no Internet permission and therefore is **not yet the production chat client**. Do not treat a successful server-image build as end-to-end chat readiness until the production Android networking/encryption client and the final session protocol have been implemented and tested together.
