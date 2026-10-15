# ADR 0005: Python for the control plane and processor

Status: accepted (2026-10-09). Its FastAPI and SQLAlchemy are being replaced by Django
([ADR 0007](0007-django.md)); Python stays.

## Context

The code we own is a registry with an API, reconcilers, and a gRPC policy processor. Go is
idiomatic for cloud-native controllers; Python matches the AI-agent ecosystem (Presidio,
the Agent Governance Toolkit's full stack, most agent frameworks) and its contributors.

## Decision

Python 3.11+ with FastAPI, SQLAlchemy 2 (SQLite for development, PostgreSQL otherwise),
httpx and grpcio. One image provides both `agentgov server` and `agentgov processor`.

## Consequences

* Fast iteration and a large contributor pool.
* The processor's hot path is bounded by Presidio and OPA latency rather than Python; it is
  stateless and scales horizontally.
* A Kubernetes operator, if needed later, can be written in Go against the same API.
