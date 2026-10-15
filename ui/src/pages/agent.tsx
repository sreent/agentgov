// One agent: who it is, what it may do, what it did, and what can be done to it.
// NOT YET PORTED: the page, and registerAgent, runLifecycle and platformBlock below, are
// placeholders with the signatures other pages use.

import { relTime } from '../lib/format';
import { PLATFORM_SOURCES } from '../lib/shared';
import { stubPage } from './stub';

export const agentPage = stubPage(/^\/agents\/([^/]+)$/, 'agents', 'Agent');

export const LIFECYCLE: Record<string, any> = {
  approve: {
    label: 'Approve', icon: 'check', cls: 'btn--primary', tone: 'primary', confirm: 'Approve agent',
    text: 'The agent becomes active and can call the tools its blueprint and grants allow. Activation needs at least one sponsor.',
    done: (n: string) => `Approved ${n}. It is now active.`,
  },
  block: {
    label: 'Block (kill switch)', icon: 'power', cls: 'btn--danger', tone: 'danger', confirm: 'Block agent',
    text: 'This is the kill switch. The gateway refuses every call from this agent as soon as OPA loads the updated policy bundle, usually within seconds. You can unblock it later.',
    done: (n: string) => `Blocked ${n}. Its tool calls are refused.`,
  },
  unblock: {
    label: 'Unblock', icon: 'undo', cls: 'btn--primary', tone: 'primary', confirm: 'Unblock agent',
    text: 'Calls from this agent will be evaluated against policy again.',
    done: (n: string) => `Unblocked ${n}.`,
  },
  delete: {
    label: 'Delete', icon: 'trash', cls: 'btn--danger-quiet', tone: 'danger', confirm: 'Delete agent',
    text: 'The agent leaves the inventory and policy denies all of its calls. Deleted agents can be restored.',
    done: (n: string) => `Deleted ${n}.`,
  },
  restore: {
    label: 'Restore', icon: 'undo', cls: 'btn--primary', tone: 'primary', confirm: 'Restore agent',
    text: 'The agent comes back as pending approval. Approve it to make it active again.',
    done: (n: string) => `Restored ${n}. It is pending approval.`,
  },
  adopt: {
    label: 'Adopt', icon: 'user-check', cls: 'btn--primary', tone: 'primary', confirm: 'Adopt agent',
    text: 'Adopting brings this unmanaged agent under governance as a pending registration. Give it an owner, at least one sponsor and a blueprint, then approve it.',
    done: (n: string) => `Adopted ${n}. It is pending approval.`,
  },
};

export const ACTIONS_BY_STATUS: Record<string, string[]> = {
  pending: ['approve', 'block', 'delete'],
  active: ['block', 'delete'],
  blocked: ['unblock', 'delete'],
  discovered: ['adopt', 'block', 'delete'],
  deleted: ['restore'],
};

// Someone a platform names as an agent's maker or owner, as AgentGov knows them.
export function makerName(m: any): string {
  if (m.name && m.email) return `${m.name} (${m.email})`;
  return m.name || m.email || `Entra ID ${m.entra_id}`;
}

export function makerRole(m: any): string {
  const where = PLATFORM_SOURCES[`platform:${m.source}`] || m.source;
  const roles = m.roles || [];
  const words = roles.includes('owner') && roles.includes('creator') ? `Made it, and owns it in ${where}`
    : roles.includes('owner') ? `Owns it in ${where}` : `Made it in ${where}`;
  let note = null;
  if (m.left) note = `left ${relTime(m.left_at)}`;
  else if (m.enabled === false) note = 'account disabled';
  else if (m.entra_id && !m.looked_up) note = 'not looked up yet';
  else if (m.entra_id && !m.known) note = 'not a user in the directory';
  return note ? `${words} · ${note}` : words;
}

// One line for a maker where there is room for one: the list, the adopt dialog.
export function makerLine(m: any): string {
  const where = PLATFORM_SOURCES[`platform:${m.source}`] || m.source;
  const note = m.left ? ' (left)' : m.enabled === false ? ' (account disabled)' : '';
  return (m.roles || []).includes('creator') ? `Made by ${makerName(m)}${note}` : `Owner in ${where}: ${makerName(m)}${note}`;
}

/** Register an agent, from its form. PLACEHOLDER until ported. */
export async function registerAgent(): Promise<void> {
  throw new Error('Not yet moved to React.');
}

/** Approve, block, unblock, delete, restore or adopt an agent, after asking. PLACEHOLDER until ported. */
export async function runLifecycle(_a: any, _action: string): Promise<void> {
  throw new Error('Not yet moved to React.');
}

/** Block (or unblock) an agent on its platform (Copilot Studio, Microsoft 365). PLACEHOLDER until ported. */
export async function platformBlock(_a: any, _where: any, _blocking: boolean): Promise<void> {
  throw new Error('Not yet moved to React.');
}
