// Access packages on agents: asking for them, deciding, renewing and revoking.
// NOT YET PORTED: placeholders with the signatures other pages use.

import type { ReactNode } from 'react';

/** An agent's access packages (agentAccessCard(agent, rows, packages, mode)). PLACEHOLDER. */
export function AgentAccessCard(_props: { agent: any; rows: any; packages: any[]; mode: string | undefined }) {
  return null;
}

/** Its Microsoft Entra access packages (entraAccessCard(agent, view)). PLACEHOLDER. */
export function EntraAccessCard(_props: { agent: any; view: any }) {
  return null;
}

/** What can be done to an assignment, as buttons. PLACEHOLDER. */
export function assignmentButtons(_row: any, _packages: any[], _agent: any): ReactNode[] {
  return [];
}

/** Ask for a package for an agent (a renewal of `current`); resolves to what was done, or null. PLACEHOLDER. */
export async function requestPackage(_agent: any, _packages: any[], _current: any): Promise<any> {
  throw new Error('Not yet moved to React.');
}

/** Approve, deny or revoke an assignment, after asking; resolves to what was done, or null. PLACEHOLDER. */
export async function assignmentAction(_row: any, _action: 'approve' | 'deny' | 'revoke'): Promise<any> {
  throw new Error('Not yet moved to React.');
}

/** Keep or remove an assignment at its review; resolves to what was done, or null. PLACEHOLDER. */
export async function reviewAssignment(_row: any, _keep: boolean): Promise<any> {
  throw new Error('Not yet moved to React.');
}

/** An organisation policy (policyCard(p)). PLACEHOLDER. */
export function PolicyCard(_props: { p: any }) {
  return null;
}

/** Try a call against the policies (whatIfCard(agents, servers, providers)). PLACEHOLDER. */
export function WhatIfCard(_props: { agents: any[]; servers: any[]; providers?: any[] }) {
  return null;
}
