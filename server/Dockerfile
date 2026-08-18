FROM vllm/vllm-openai:v0.26.0

LABEL org.opencontainers.image.title="PPIO H20 Private AI Gateway"
LABEL org.opencontainers.image.description="Privacy-hardened self-hosted vLLM gateway"

USER root
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VLLM_LOGGING_LEVEL=ERROR \
    VLLM_ENABLE_CUDA_COMPATIBILITY=1 \
    VLLM_NO_USAGE_STATS=1 \
    VLLM_DO_NOT_TRACK=1 \
    DO_NOT_TRACK=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    HF_HUB_DISABLE_UPDATE_CHECK=1 \
    VLLM_MEDIA_URL_ALLOW_REDIRECTS=0 \
    HOME=/home/vllm \
    XDG_CACHE_HOME=/home/vllm/.cache \
    HF_HOME=/home/vllm/.cache/huggingface \
    VLLM_CACHE_ROOT=/home/vllm/.cache/vllm

WORKDIR /opt/private-ai
COPY requirements.txt /opt/private-ai/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /opt/private-ai/requirements.txt
COPY gateway.py make_ephemeral_tls.py entrypoint.sh set_admin_totp.sh /opt/private-ai/
RUN python3 -c "import ast,pathlib; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in ('/opt/private-ai/gateway.py','/opt/private-ai/make_ephemeral_tls.py')]" \
    && bash -n /opt/private-ai/entrypoint.sh /opt/private-ai/set_admin_totp.sh \
    && mkdir -p /home/vllm/.cache/huggingface /home/vllm/.cache/vllm \
    && chown -R 2000:0 /home/vllm /opt/private-ai \
    && chmod 700 /home/vllm /home/vllm/.cache /home/vllm/.cache/huggingface /home/vllm/.cache/vllm \
    && chmod 700 /opt/private-ai/entrypoint.sh /opt/private-ai/set_admin_totp.sh \
    && chmod 600 /opt/private-ai/gateway.py /opt/private-ai/make_ephemeral_tls.py

# vLLM's official CUDA image includes a non-root vllm user (UID 2000).
USER 2000:0

EXPOSE 8443
ENTRYPOINT ["/opt/private-ai/entrypoint.sh"]
