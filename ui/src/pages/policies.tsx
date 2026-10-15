// NOT YET PORTED: the page, and the policy actions and actsFor, are placeholders.

import type { ReactNode } from 'react';
import { stubPage } from './stub';

export const policiesPage = stubPage(/^\/policies$/, 'policies', 'Policies');

/** Who a blueprint's (or an agent's) agents act for, in words. PLACEHOLDER. */
export function actsFor(_x: any): ReactNode {
  return null;
}

export async function policyFormFlow(_p: any): Promise<void> {
  throw new Error('Not yet moved to React.');
}

export async function togglePolicy(_p: any): Promise<void> {
  throw new Error('Not yet moved to React.');
}

export async function deletePolicy(_p: any): Promise<void> {
  throw new Error('Not yet moved to React.');
}
