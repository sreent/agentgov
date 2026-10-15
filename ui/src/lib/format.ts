// Numbers, words and times as people read them.

export const numberFmt = new Intl.NumberFormat();
export const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
export const stampFmt = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});
export const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
export const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
export const dayLongFmt = new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
export const clockFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
export const shortDayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export const fmt = (n: number | null | undefined): string => numberFmt.format(n ?? 0);

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${fmt(n)} ${n === 1 ? one : many}`;
}

export function cap(text: string | null | undefined): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
}

export function humanize(text: unknown): string {
  return cap(String(text ?? '').replace(/[_]+/g, ' '));
}

export function shortHash(value: string | null | undefined, head = 8, tail = 6): string {
  if (!value) return '';
  return value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
}

export function relTime(iso: string): string {
  const sec = (new Date(iso).getTime() - Date.now()) / 1000;
  const abs = Math.abs(sec);
  if (abs < 45) return sec <= 0 ? 'just now' : 'in a few seconds';
  const table: [number, Intl.RelativeTimeFormatUnit, number][] = [
    [3600, 'minute', 60], [86400, 'hour', 3600], [86400 * 7, 'day', 86400],
    [86400 * 30, 'week', 604800], [86400 * 365, 'month', 2592000], [Infinity, 'year', 31536000],
  ];
  for (const [limit, unit, div] of table) {
    if (abs < limit) return relFmt.format(Math.round(sec / div), unit);
  }
  return '';
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${fmt(n)} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function initials(label: string | null | undefined): string {
  const base = String(label || '?').split('@')[0];
  const parts = base.split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] || '?') + (parts[1]?.[0] || '')).toUpperCase();
}

export function countBy<T>(list: T[], key: keyof T | ((item: T) => unknown)): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of list) {
    const k = String(typeof key === 'function' ? key(item) : item[key]);
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

// A file name's time: 2026-10-15-09-30-00.
export function fileStamp(): string {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}

// Class names, leaving out those that don't apply.
export function cx(...names: (string | false | null | undefined)[]): string {
  return names.filter(Boolean).join(' ');
}
