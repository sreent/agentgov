# Schemas for the chart's checks

JSON schemas of custom resources the chart renders that the
[CRDs catalog](https://github.com/datreeio/CRDs-catalog) doesn't have, for kubeconform
in `scripts/ci.sh`:

* `spire.spiffe.io/clusterspiffeid_v1alpha1.json`: SPIRE's ClusterSPIFFEID
  (`internalTLS.spire`), from the CRD in the `spire-crds` chart 0.6.1
  (https://github.com/spiffe/helm-charts-hardened, Apache License 2.0), with unknown
  fields refused.
