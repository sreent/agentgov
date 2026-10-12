#!/usr/bin/env bash
# Regenerates the gRPC stubs the governance processor serves: agentgateway's ExtMcp
# (tool calls) and Envoy's external processing (agents' answers to other agents).
set -euo pipefail
cd "$(dirname "$0")/../src"
python -m grpc_tools.protoc -I . \
  --python_out=. --pyi_out=. --grpc_python_out=. \
  agentgov/processor/proto/ext_mcp.proto agentgov/processor/proto/ext_proc.proto
