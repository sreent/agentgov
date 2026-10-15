// Short messages about what just happened, in the corner; a failure stays longer, and is
// announced at once.

import { useSyncExternalStore, type ReactNode } from 'react';
import { Icon } from './Icon';

export type ToastTone = 'good' | 'critical' | 'warning' | 'neutral';

interface Toast {
  id: number;
  message: ReactNode;
  tone: ToastTone;
}

let toasts: Toast[] = [];
let nextId = 0;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

function remove(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

export function toast(message: ReactNode, { tone = 'good', timeout }: { tone?: ToastTone; timeout?: number } = {}): void {
  const id = ++nextId;
  toasts = [...toasts, { id, message, tone }];
  emit();
  setTimeout(() => remove(id), timeout ?? (tone === 'critical' ? 10000 : 5000));
}

export function clearToasts(): void {
  toasts = [];
  emit();
}

/** Wrap an async handler so that a failure shows as a toast instead of being lost. */
export function guarded<A extends unknown[]>(fn: (...args: A) => unknown): (...args: A) => Promise<void> {
  return async (...args: A) => {
    try {
      await fn(...args);
    } catch (err: any) {
      toast(err?.message || String(err), { tone: 'critical' });
    }
  };
}

const TONE_ICONS: Record<string, string> = { good: 'check-circle', critical: 'alert-circle', warning: 'triangle' };

export function Toasts() {
  const list = useSyncExternalStore((l) => {
    listeners.add(l);
    return () => listeners.delete(l);
  }, () => toasts);
  return (
    <div className="toasts" aria-live="polite" aria-relevant="additions">
      {list.map((t) => (
        <div key={t.id} className="toast" data-tone={t.tone} role={t.tone === 'critical' ? 'alert' : undefined}>
          <Icon name={TONE_ICONS[t.tone] || 'info'} />
          <div className="toast-body">{t.message}</div>
          <button type="button" className="icon-btn" aria-label="Dismiss notification" onClick={() => remove(t.id)}>
            <Icon name="x" />
          </button>
        </div>
      ))}
    </div>
  );
}
