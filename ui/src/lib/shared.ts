// What several pages use: names' rules, the platforms agents run on, features' modes, and
// actions on many at once.

import { api } from './api';
import { fmt } from './format';

export const RISK_TIERS = ['minimal', 'low', 'medium', 'high', 'critical'];
export const NAME_HINT = 'Lowercase letters, digits and hyphens, starting and ending with a letter or digit.';

// Agents built on other platforms (Microsoft 365 Copilot, Copilot Studio, Microsoft Foundry,
// AWS, Google Cloud, Salesforce, Databricks). They never call the gateway, so AgentGov
// governs what their platform reports about them.
export const PLATFORM_SOURCES: Record<string, string> = {
  'platform:microsoft-365': 'Microsoft 365',
  'platform:copilot-studio': 'Copilot Studio',
  'platform:entra-agent-id': 'Microsoft Entra Agent ID',
  'platform:aws': 'AWS',
  'platform:google-cloud': 'Google Cloud',
  'platform:salesforce': 'Salesforce',
  'platform:databricks': 'Databricks',
  'platform:microsoft-foundry': 'Microsoft Foundry',
};
// The platforms a connector of AgentGov's own reads: each reports its agents the same way.
export const INVENTORY_SOURCES = new Set(['aws', 'google-cloud', 'salesforce', 'databricks', 'microsoft-foundry']);
// The platforms whose agents AgentGov can block there (an Entra identity alone isn't one).
export const BLOCKABLE_SOURCES = new Set(['copilot-studio', 'microsoft-365']);

export function platformOf(a: { source?: string | null } | null | undefined): string | null {
  return (a?.source && PLATFORM_SOURCES[a.source]) || null;
}

// An agent another platform runs, which AgentGov read from it (not through the gateway).
export function isPlatformAgent(a: { source?: string | null }): boolean {
  return (a.source || '').startsWith('platform:');
}

export const MODE_WORDS: Record<string, string> = {
  off: 'Off', on: 'On', monitor: 'Monitor', enforce: 'Enforce',
  inform: 'Inform', triage: 'Triage', contain: 'Contain', decide: 'Decide',
};

/** Each feature's mode, by its key. */
export async function featureModes(): Promise<Record<string, string>> {
  const view = await api<{ features: { key: string; mode: string }[] }>('v1/features');
  return Object.fromEntries(view.features.map((f) => [f.key, f.mode]));
}

// What differs from the defaults: features monitored, and features turned off.
export function featureSummary(list: { mode: string; default: string }[]): string {
  const monitored = list.filter((f) => f.mode === 'monitor' && f.default !== 'monitor').length;
  const off = list.filter((f) => f.mode === 'off' && f.default !== 'off').length;
  const parts = [monitored ? `${fmt(monitored)} monitored` : null, off ? `${fmt(off)} turned off` : null].filter(Boolean);
  return parts.length ? `Features: ${parts.join(', ')}` : 'Features: the defaults';
}

export interface ManyResult { done: any[]; left: { why: string; title?: string; [key: string]: any }[] }

// An action on many at once, in turns of at most this many: the control plane takes them
// in one transaction each.
const AT_ONCE = 500;
export async function inTurns(path: string, body: Record<string, any>, key: string): Promise<ManyResult> {
  const out: ManyResult = { done: [], left: [] };
  for (let i = 0; i < body[key].length; i += AT_ONCE) {
    const part = await api<ManyResult>(path, { method: 'POST', body: { ...body, [key]: body[key].slice(i, i + AT_ONCE) } });
    out.done.push(...part.done);
    out.left.push(...part.left);
  }
  return out;
}
