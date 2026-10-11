# Docker Compose stack

The whole of AgentGov on one machine, with the demo's tool server, model and stand-ins,
for evaluation and development:

```bash
docker compose up -d --build --wait      # from this folder
```

[Run AgentGov on your machine](../../docs/deploy/local.md#docker-compose) is the guide: the
endpoints, signing in, settings and secrets, the optional Langfuse and Granite Guardian
overrides, connecting Microsoft 365, upgrading and troubleshooting.
[Configuration](../../docs/configuration.md#docker-compose) explains `.env` and
`docker-compose.override.yml`. Read [SECURITY.md](../../SECURITY.md#deploying-safely)
before anyone else can reach the stack.
