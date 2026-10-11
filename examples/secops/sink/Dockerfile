ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
WORKDIR /app
RUN useradd --uid 10001 sink
COPY server.py .
USER sink
EXPOSE 9300
CMD ["python", "server.py"]
