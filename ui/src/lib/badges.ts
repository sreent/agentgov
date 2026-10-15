// The menu's counts: approvals waiting, and issues open (in the tone of the worst).

import { useSyncExternalStore } from 'react';
import { api, apiRaw } from './api';
import { countBy } from './format';
import { isPerson, personPages } from './session';

export interface Badge { count: number; tone: string }
export interface Badges { approvals: Badge; findings: Badge }

let badges: Badges = { approvals: { count: 0, tone: '' }, findings: { count: 0, tone: '' } };
const listeners = new Set<() => void>();

function update(pendingApprovals: number, findings: { open: number; by_severity: Record<string, number> }) {
  const by = findings.by_severity;
  badges = {
    approvals: { count: pendingApprovals, tone: pendingApprovals ? 'warning' : '' },
    findings: { count: findings.open, tone: by.critical ? 'critical' : by.high ? 'serious' : findings.open ? 'warning' : '' },
  };
  listeners.forEach((l) => l());
}

export function clearBadges(): void {
  update(0, { open: 0, by_severity: {} });
}

/** Count again: after a change that may have changed what waits. */
export async function refreshBadges(): Promise<void> {
  try {
    if (isPerson()) {
      const pages = personPages();
      const [pending, issues] = await Promise.all([
        pages.includes('approvals') ? api<unknown[]>('v1/me/approvals?status=pending') : [],
        pages.includes('findings') ? api<{ severity: string }[]>('v1/me/issues?status=open') : [],
      ]);
      update(pending.length, { open: issues.length, by_severity: countBy(issues, 'severity') });
      return;
    }
    // How many are open, and whether any is critical or high: counted by the control
    // plane, however many there are.
    const count = async (query: string) => {
      const res = await apiRaw(`v1/findings?status=open&limit=1${query}`);
      return Number(res.headers.get('X-Total-Count') || 0);
    };
    const [waiting, open, critical, high] = await Promise.all([
      api<{ total: number }>('v1/inbox'), count(''), count('&severity=critical'), count('&severity=high'),
    ]);
    update(waiting.total, { open, by_severity: { critical, high } });
  } catch {
    /* badges are a convenience; the pages show the real state */
  }
}

export function useBadges(): Badges {
  return useSyncExternalStore((l) => {
    listeners.add(l);
    return () => listeners.delete(l);
  }, () => badges);
}
