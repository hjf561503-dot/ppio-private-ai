#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ulimit -c 0 || true

RAMDIR=/dev/shm/private-ai
TLS_DIR="$RAMDIR/tls"
VLLM_UDS="$RAMDIR/vllm.sock"
VLLM_PID_FILE="$RAMDIR/vllm.pid"
mkdir -p "$RAMDIR" "$TLS_DIR"
chmod 700 "$RAMDIR" "$TLS_DIR"

MODEL="${MODEL:-TrevorJS/gemma-4-26B-A4B-it-uncensored}"
MODEL_REVISION="${MODEL_REVISION:-fc582b971b5b6f7738d311d7ea2b1b7b446ff0a1}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-50000}"
GPU_MEM_UTIL="${GPU_MEMORY_UTILIZATION:-0.90}"
GATEWAY_PORT="${GATEWAY_PORT:-8443}"
export VLLM_UDS
export VLLM_KEY_FILE="$RAMDIR/vllm.key"
export VLLM_PID_FILE
export TLS_DIR
export VLLM_LOGGING_LEVEL="${VLLM_LOGGING_LEVEL:-ERROR}"

python3 - <<'PY' > "$VLLM_KEY_FILE"
import secrets
print(secrets.token_urlsafe(64))
PY
chmod 600 "$VLLM_KEY_FILE"
VLLM_KEY="$(cat "$VLLM_KEY_FILE")"

TLS_LINE="$(python3 /opt/private-ai/make_ephemeral_tls.py)"
echo "[SECURITY] $TLS_LINE"
echo "[SECURITY] Verify/pin this fingerprint out-of-band before sending private chat data."

HELP="$(vllm serve --help 2>&1 || true)"
VARGS=(serve "$MODEL" --revision "$MODEL_REVISION" --uds "$VLLM_UDS" --max-model-len "$MAX_MODEL_LEN" --gpu-memory-utilization "$GPU_MEM_UTIL" --api-key "$VLLM_KEY")
if grep -q -- '--disable-uvicorn-access-log' <<<"$HELP"; then VARGS+=(--disable-uvicorn-access-log); fi
if grep -q -- '--disable-log-stats' <<<"$HELP"; then VARGS+=(--disable-log-stats); fi
if grep -q -- '--no-enable-log-requests' <<<"$HELP"; then VARGS+=(--no-enable-log-requests); fi
if grep -q -- '--no-enable-log-outputs' <<<"$HELP"; then VARGS+=(--no-enable-log-outputs); fi
if grep -q -- '--no-enable-log-deltas' <<<"$HELP"; then VARGS+=(--no-enable-log-deltas); fi
if grep -q -- '--no-log-error-stack' <<<"$HELP"; then VARGS+=(--no-log-error-stack); fi
if grep -q -- '--uvicorn-log-level' <<<"$HELP"; then VARGS+=(--uvicorn-log-level error); fi

vllm "${VARGS[@]}" >"$RAMDIR/vllm.stdout" 2>"$RAMDIR/vllm.stderr" &
VLLM_PID=$!
printf '%s\n' "$VLLM_PID" > "$VLLM_PID_FILE"
chmod 600 "$VLLM_PID_FILE"

cleanup() {
  if [[ -n "${GATEWAY_PID:-}" ]]; then kill "$GATEWAY_PID" 2>/dev/null || true; fi
  if [[ -n "${VLLM_PID:-}" ]]; then kill "$VLLM_PID" 2>/dev/null || true; fi
  rm -rf "$RAMDIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

READY=0
for _ in $(seq 1 300); do
  if [[ -S "$VLLM_UDS" ]] && curl --unix-socket "$VLLM_UDS" -fsS \
       -H "Authorization: Bearer $VLLM_KEY" http://localhost/v1/models >/dev/null 2>&1; then
    READY=1
    break
  fi
  if ! kill -0 "$VLLM_PID" 2>/dev/null; then
    echo "[ERROR] vLLM exited during startup. Last stderr lines:" >&2
    tail -n 80 "$RAMDIR/vllm.stderr" >&2 || true
    exit 1
  fi
  sleep 2
done
if [[ "$READY" != "1" ]]; then
  echo "[ERROR] vLLM did not become ready before timeout." >&2
  exit 1
fi

uvicorn gateway:app \
  --app-dir /opt/private-ai \
  --host 0.0.0.0 \
  --port "$GATEWAY_PORT" \
  --no-access-log \
  --log-level error \
  --no-server-header \
  --ssl-keyfile "$TLS_DIR/server.key" \
  --ssl-certfile "$TLS_DIR/server.crt" &
GATEWAY_PID=$!
wait "$GATEWAY_PID"
