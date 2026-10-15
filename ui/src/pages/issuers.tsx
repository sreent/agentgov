// Agents' own identities: the identity issuers whose tokens agents authenticate with.
// NOT YET PORTED beyond what the agent page uses.

// Identity issuers by kind: name, a subject its tokens carry, and its issuer.
export const ISSUER_KINDS: Record<string, [name: string, subject: string, issuer: string]> = {
  kubernetes: ['Kubernetes', 'system:serviceaccount:agents:support-bot', 'https://kubernetes.default.svc.cluster.local'],
  spiffe: ['SPIFFE', 'spiffe://example.org/ns/agents/sa/support-bot', 'spiffe://example.org'],
  oidc: ['OpenID Connect', '6f1c5e1a-…', 'https://login.microsoftonline.com/<tenant>/v2.0'],
};
export const ISSUER_KEYS_HINT: Record<string, string> = {
  kubernetes: "The cluster's issuer discovery URL, when Keycloak, or AgentGov for the gateway, can't read its keys at the issuer itself. Empty: at the issuer (for Keycloak's own cluster, with Keycloak's service account).",
  spiffe: 'The SPIFFE bundle endpoint (from SPIRE, say) with the trust domain\'s keys.',
  oidc: "The JWKS URL. Empty: found from the issuer's discovery document.",
};

export const issuerKind = (kind: string): string => (ISSUER_KINDS[kind] || [kind])[0];

// Microsoft Entra ID, whose app-only tokens name an agent identity by its object ID
// (v2 tokens' issuer, or v1's).
export const isEntra = (issuer: { issuer?: string } | null | undefined): boolean =>
  /^https:\/\/(login\.microsoftonline\.(com|us)|sts\.windows\.net)\//.test(issuer?.issuer || '');
