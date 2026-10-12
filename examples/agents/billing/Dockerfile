# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
WORKDIR /app
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir "mcp==2.3.0" "pyjwt[crypto]==2.15.1" \
    && useradd --uid 10001 billing
COPY server.py .
USER billing
EXPOSE 9600
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9600"]
