# syntax=docker/dockerfile:1.7
# AgentGov control plane and governance processor (one image, two commands):
#   docker run ... agentgov server      # control plane API, UI, OPA bundle server
#   docker run ... agentgov processor   # agentgateway ExtMcp policy server
ARG PYTHON_IMAGE=python:3.12-slim
ARG OPA_IMAGE=openpolicyagent/opa:1.21.1-static

# The opa binary validates organisation Rego policies before they are distributed.
FROM ${OPA_IMAGE} AS opa

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=opa /opa /usr/local/bin/opa
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# An optional build secret "extra_ca" lets builds behind TLS-inspecting proxies trust them:
#   docker build --secret id=extra_ca,src=/path/to/ca.pem .
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir ".[postgres,otlp-protobuf]" \
    && useradd --uid 10001 --create-home agentgov \
    # Shared with agentgateway: the control plane writes its config here.
    && mkdir -p /gateway && chown agentgov /gateway
USER agentgov
WORKDIR /home/agentgov
# psycopg's own copies of libpq and OpenSSL look for trusted certificate authorities
# where Debian doesn't keep them: point them there, so that database URLs can verify the
# server with sslrootcert=system.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EXPOSE 8000 50051
ENTRYPOINT ["agentgov"]
CMD ["server"]
