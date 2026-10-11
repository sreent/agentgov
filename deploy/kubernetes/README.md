# Values and manifests for the cloud guides

The [Helm chart](../helm/agentgov) installs AgentGov on any Kubernetes cluster. Each folder here
holds what one cloud guide adds: the chart's values (`values.yaml`) and the manifests applied
beside the chart (`manifests/`), such as the Secret synced from the cloud's secret store and the
load balancer's configuration.

| Folder | Guide |
|---|---|
| [`aks`](aks) | [Azure](../../docs/deploy/azure.md) |
| [`eks`](eks) | [AWS](../../docs/deploy/aws.md) |
| [`gke`](gke) | [Google Cloud](../../docs/deploy/gcp.md) |

The files use example names (`agentgov.example.com`) and placeholders in angle brackets, such
as `<keyvault>`, which the guides replace with yours. CI renders each `values.yaml` with the
chart and validates the result and the manifests with kubeconform.
