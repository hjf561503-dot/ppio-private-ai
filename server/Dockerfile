FROM vllm/vllm-openai:v0.26.0

LABEL org.opencontainers.image.title="PPIO H20 Private AI Gateway"
LABEL org.opencontainers.image.description="Privacy-hardened self-hosted vLLM gateway"

USER root
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VLLM_LOGGING_LEVEL=ERROR

WORKDIR /opt/private-ai
COPY requirements.txt /opt/private-ai/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /opt/private-ai/requirements.txt
COPY gateway.py make_ephemeral_tls.py entrypoint.sh set_admin_totp.sh /opt/private-ai/
RUN chown -R 2000:0 /opt/private-ai \
    && chmod 700 /opt/private-ai/entrypoint.sh /opt/private-ai/set_admin_totp.sh \
    && chmod 600 /opt/private-ai/gateway.py /opt/private-ai/make_ephemeral_tls.py

# vLLM's official CUDA image includes a non-root vllm user (UID 2000).
USER 2000:0

EXPOSE 8443
ENTRYPOINT ["/opt/private-ai/entrypoint.sh"]
