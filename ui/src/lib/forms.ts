// What people type in forms, as the API's JSON. Lists are typed "a, b" or one per line,
// labels "key=value", and tool grants "server: tool, tool" with one server per line. The
// control plane validates everything again; these only turn the text into the API's shapes.

export function parseList(text: unknown): string[] {
  return String(text || '').split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
}

export function parseLabels(text: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const item of parseList(text)) {
    const eq = item.indexOf('=');
    if (eq < 1) throw new Error(`Write labels as key=value, separated by commas ("${item}" has no "=").`);
    out[item.slice(0, eq).trim()] = item.slice(eq + 1).trim();
  }
  return out;
}

export function formatLabels(labels: Record<string, string> | null | undefined): string {
  return Object.entries(labels || {}).map(([k, v]) => `${k}=${v}`).join(', ');
}

export interface Grant { server: string; tools: string[] }

export function parseGrants(text: unknown): Grant[] {
  return String(text || '').split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const colon = line.indexOf(':');
    if (colon < 1) throw new Error(`Write each grant as "server: tool, tool" ("${line}" has no server).`);
    const server = line.slice(0, colon).trim();
    const tools = parseList(line.slice(colon + 1));
    if (!tools.length) throw new Error(`List the tools granted on ${server}, or * for all of them.`);
    return { server, tools };
  });
}

export function formatGrants(grants: Grant[] | null | undefined): string {
  return (grants || []).map((g) => `${g.server}: ${g.tools.join(', ')}`).join('\n');
}

export interface ModelAccess { provider: string; models: string[] }

// Model access is typed like tool grants: "provider: model, model", one provider per line.
export function parseModelAccess(text: unknown): ModelAccess[] {
  return String(text || '').split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const colon = line.indexOf(':');
    if (colon < 1) throw new Error(`Write each line as "provider: model, model" ("${line}" has no provider).`);
    const provider = line.slice(0, colon).trim();
    const models = parseList(line.slice(colon + 1));
    if (!models.length) throw new Error(`List the models of ${provider} it may call, or * for all of them.`);
    return { provider, models };
  });
}

export function formatModelAccess(access: ModelAccess[] | null | undefined): string {
  return (access || []).map((g) => `${g.provider}: ${g.models.join(', ')}`).join('\n');
}

export function parseBudget(text: unknown): number | null {
  if (!text) return null;
  const n = Number(text);
  if (!Number.isInteger(n) || n < 0) throw new Error('The daily token budget is a whole number of tokens, or empty.');
  return n;
}

export const orNull = (text: string | null | undefined): string | null => text || null;
