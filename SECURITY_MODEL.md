# Security model

## Goal

Minimize readable chat plaintext outside volatile process/GPU memory on a normal PPIO H20 instance, while keeping the inference model self-hosted.

## Hard boundary

H20 is not NVIDIA Confidential Computing. A cloud provider or attacker with sufficient host/hypervisor control can potentially inspect plaintext while inference is active. This design therefore protects **data at rest, ordinary logs, network transit, replay/authentication, and accidental disclosure**, not a malicious hypervisor.

## Trust and data-flow rules

1. The Android device is the long-term identity root. Production target: non-exportable P-256 key in Android StrongBox.
2. The server's public entry point is TLS port 8443 only.
3. vLLM has no public or loopback TCP port; it uses a Unix-domain socket located in `/dev/shm`.
4. TLS identity is per-boot and RAM-only. The client must pin the certificate fingerprint out-of-band.
5. Every state-changing/private request is device-signed and contains a timestamp, nonce and request-body hash.
6. Session confidentiality adds X25519 + HKDF-SHA256 + AES-256-GCM inside TLS.
7. No chat database is implemented on the server.
8. Prompt/response/access/stat logging is explicitly disabled where the installed vLLM supports the corresponding flags.
9. Core dumps are disabled; Python bytecode persistence is disabled in the image.
10. The container runs as a non-root user.
11. Admin lockdown requires device authentication plus TOTP, then clears sessions and destroys the RAM-only vLLM API credential.
12. A failed/unknown login never destroys storage; this prevents attackers from turning authentication failure into a remote self-destruct denial-of-service primitive.

## Intentionally not persisted

- Prompt bodies
- Model response bodies
- Conversation history/database
- TLS private key
- vLLM API credential
- Session encryption keys
- Admin TOTP secret

## Still observable to the cloud/network layer

- Account identity and instance metadata
- GPU/CPU/storage usage
- Source/destination IPs, timing and traffic volume
- Open public TCP port
- Plaintext that exists in CPU RAM/GPU VRAM during active inference if the host/hypervisor is malicious
