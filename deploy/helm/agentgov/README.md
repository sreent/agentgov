# AgentGov Helm chart

Installs AgentGov on Kubernetes: the control plane, the governance processor, OPA,
agentgateway, Presidio and the OpenTelemetry Collector; PostgreSQL, for evaluation; and
Keycloak, in development mode for evaluation or in production mode with your PostgreSQL.

```bash
# From a clone of the repository, with an image you built
helm install agentgov deploy/helm/agentgov -n agentgov --create-namespace --wait \
  --set image.repository=REGISTRY/agentgov --set image.tag=0.1.0

# Once 0.1.0 is released
helm install agentgov oci://ghcr.io/sreent/charts/agentgov --version 0.1.0 \
  -n agentgov --create-namespace --wait
```

To run less of it, start from a profile:
[`profiles/inventory.yaml`](profiles/inventory.yaml), the agents on your platforms, their
findings and issues, with no gateway, OPA, Presidio or Keycloak; or
[`profiles/monitor.yaml`](profiles/monitor.yaml), the gateway with every control watching
rather than stopping, without Presidio
([profiles](../../../docs/deploy/kubernetes.md#profiles)).

The defaults are for evaluation. The guides cover the rest:

* [Kubernetes](../../../docs/deploy/kubernetes.md): trying it, the image, what to change
  before others rely on it, every value, upgrading
* [Google Cloud](../../../docs/deploy/gcp.md), [Azure](../../../docs/deploy/azure.md) and
  [AWS](../../../docs/deploy/aws.md): the cloud's database, secrets, load balancer and
  certificates
* [Configuration](../../../docs/configuration.md): every setting, and which values set them
* [Requirements](../../../docs/requirements.md): versions, resources and network

[`values.yaml`](values.yaml) documents every value. CI checks the chart with `helm lint`,
renders it with the default, production, profiles' and cloud values and validates the
result with kubeconform, runs its pods with Docker (`scripts/ci.sh --e2e`) and installs it on kind
(`scripts/ci.sh --kind`), each time with the demo.
