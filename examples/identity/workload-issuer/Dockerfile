# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
WORKDIR /app
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir "pyjwt[crypto]==2.15.1" \
    && useradd --uid 10001 issuer
COPY server.py .
USER issuer
EXPOSE 9200
CMD ["python", "server.py"]
