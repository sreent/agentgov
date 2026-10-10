#!/usr/bin/env bash
# Regenerates the ExtMcp gRPC stubs used by the governance processor.
set -euo pipefail
cd "$(dirname "$0")/../src"
python -m grpc_tools.protoc -I . \
  --python_out=. --pyi_out=. --grpc_python_out=. \
  agentgov/processor/proto/ext_mcp.proto
