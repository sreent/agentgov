ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
WORKDIR /app
RUN useradd --uid 10001 model
COPY server.py .
USER model
EXPOSE 9100
CMD ["python", "server.py"]
