// What each status is called, and its tone and icon: kind -> value -> [tone, icon, label].

import { humanize } from './format';

export type Tone = 'good' | 'warning' | 'serious' | 'critical' | 'neutral' | 'accent';
type Meta = [tone: Tone, icon: string, label: string];

export const STATUS: Record<string, Record<string, Meta>> = {
  agent: {
    active: ['good', 'check-circle', 'Active'],
    pending: ['warning', 'clock', 'Pending approval'],
    blocked: ['critical', 'ban', 'Blocked'],
    discovered: ['serious', 'eye', 'Unmanaged'],
    deleted: ['neutral', 'trash', 'Deleted'],
  },
  risk: {
    low: ['neutral', 'minus', 'Low risk'],
    medium: ['warning', 'alert-circle', 'Medium risk'],
    high: ['serious', 'triangle', 'High risk'],
    critical: ['critical', 'octagon', 'Critical risk'],
  },
  severity: {
    critical: ['critical', 'octagon', 'Critical'],
    high: ['serious', 'triangle', 'High'],
    medium: ['warning', 'alert-circle', 'Medium'],
    low: ['neutral', 'minus', 'Low'],
    info: ['neutral', 'info', 'Info'],
  },
  decision: {
    allow: ['good', 'check-circle', 'Allowed'],
    deny: ['critical', 'ban', 'Denied'],
    require_approval: ['warning', 'user-check', 'Needs approval'],
  },
  approval: {
    pending: ['warning', 'clock', 'Pending'],
    approved: ['good', 'check-circle', 'Approved'],
    denied: ['critical', 'ban', 'Denied'],
    used: ['neutral', 'check-double', 'Used'],
    expired: ['neutral', 'clock', 'Expired'],
    cancelled: ['neutral', 'minus', 'Cancelled'],
  },
  server: {
    approved: ['good', 'check-circle', 'Approved'],
    pending: ['warning', 'clock', 'Pending approval'],
    blocked: ['critical', 'ban', 'Blocked'],
    unregistered: ['serious', 'alert-circle', 'Unregistered'],
  },
  finding: {
    open: ['warning', 'alert-circle', 'Open'],
    resolved: ['good', 'check-circle', 'Resolved'],
    dismissed: ['neutral', 'minus', 'Dismissed'],
    accepted: ['neutral', 'shield-check', 'Risk accepted'],
  },
  access: {
    requested: ['warning', 'clock', 'Requested'],
    active: ['good', 'check-circle', 'Active'],
    expired: ['serious', 'triangle', 'Expired'],
    denied: ['neutral', 'ban', 'Denied'],
    revoked: ['neutral', 'minus', 'Revoked'],
    renewed: ['neutral', 'check-double', 'Renewed'],
  },
  entra_access: {
    delivered: ['good', 'check-circle', 'Delivered'],
    delivering: ['warning', 'clock', 'Delivering'],
    partiallyDelivered: ['warning', 'triangle', 'Partly delivered'],
    deliveryFailed: ['critical', 'octagon', 'Delivery failed'],
  },
  rule: {
    waiting: ['neutral', 'clock', 'Waiting'],
    due: ['warning', 'alert-circle', 'Due'],
    acted: ['serious', 'check-double', 'Acted on'],
    exempt: ['neutral', 'shield-check', 'Held back'],
    cannot: ['neutral', 'ban', "Can't act"],
    monitored: ['neutral', 'eye', 'Would have acted'],
    off: ['neutral', 'minus', 'Off'],
  },
  classification: {
    'high-risk': ['serious', 'triangle', 'High-risk'],
    transparency: ['warning', 'eye', 'Transparency obligations'],
    minimal: ['good', 'check-circle', 'Minimal risk'],
    prohibited: ['critical', 'octagon', 'Prohibited practice'],
    'not-ai-system': ['neutral', 'minus', 'Not an AI system'],
    none: ['neutral', 'info', 'Not classified'],
  },
  compliance: {
    in_place: ['good', 'check-circle', 'In place'],
    partly: ['warning', 'alert-circle', 'Partly'],
    configured: ['warning', 'eye', 'Configured, not observed'],
    not_set_up: ['neutral', 'minus', 'Not set up'],
    attention: ['critical', 'octagon', 'Needs attention'],
    outside: ['neutral', 'info', 'Outside AgentGov'],
  },
  notification: {
    pending: ['neutral', 'clock', 'Sending'],
    sent: ['good', 'check-circle', 'Sent'],
    failed: ['critical', 'octagon', 'Not sent'],
  },
  apikey: {
    active: ['good', 'check-circle', 'Active'],
    expired: ['warning', 'clock', 'Expired'],
    revoked: ['neutral', 'ban', 'Revoked'],
  },
  person: {
    signed_in: ['good', 'check-circle', 'Signed in'],
    signed_out: ['neutral', 'minus', 'Signed out'],
    refused: ['critical', 'ban', 'Refused'],
  },
  sync: {
    ok: ['good', 'check-circle', 'Succeeded'],
    failed: ['critical', 'octagon', 'Failed'],
  },
  connector: {
    approved: ['good', 'check-circle', 'Approved'],
    unapproved: ['serious', 'triangle', 'Not approved'],
    unchecked: ['neutral', 'minus', 'Not approved'],
  },
  connection: {
    ok: ['good', 'check-circle', 'Working'],
    waiting: ['neutral', 'clock', 'Waiting for its first run'],
    missing_permission: ['warning', 'triangle', 'Missing a permission'],
    failing: ['critical', 'octagon', 'Failing'],
    off: ['neutral', 'minus', 'Not set up'],
    available: ['neutral', 'user-check', 'Ready for admins signed in with Entra ID'],
    import: ['neutral', 'upload', 'Import only'],
    out_of_date: ['warning', 'triangle', 'Out of date'],
    monitor: ['neutral', 'eye', 'Monitoring'],
    enforce: ['good', 'shield-check', 'Enforcing'],
    turned_off: ['neutral', 'power', 'Turned off in Features'],
    partial: ['warning', 'triangle', 'Partly read'],
  },
  mode: {
    enforce: ['good', 'shield-check', 'Enforce'],
    monitor: ['warning', 'eye', 'Monitor'],
    on: ['good', 'check-circle', 'On'],
    off: ['neutral', 'minus', 'Off'],
    inform: ['good', 'secops', 'Inform'],
    triage: ['good', 'check-circle', 'Triage'],
    contain: ['warning', 'ban', 'Contain'],
    decide: ['warning', 'user-check', 'Decide'],
  },
  destination: {
    active: ['good', 'check-circle', 'Active'],
    paused: ['neutral', 'minus', 'Paused'],
  },
  ticket: {
    pending: ['neutral', 'clock', 'Opening'],
    open: ['good', 'check-circle', 'Kept in step'],
    closed: ['neutral', 'minus', 'Closed'],
    failed: ['critical', 'octagon', "Couldn't open"],
  },
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const TONE_COLOR: Record<Tone, string> = {
  good: 'var(--good)', warning: 'var(--warning)', serious: 'var(--serious)',
  critical: 'var(--critical)', neutral: 'var(--neutral)', accent: 'var(--accent)',
};

export function statusMeta(kind: string, value: string | null | undefined): Meta {
  return (value != null && STATUS[kind]?.[value]) || ['neutral', 'info', value ? humanize(value) : 'Unknown'];
}

export function toneOf(kind: string, value: string | null | undefined): Tone {
  return statusMeta(kind, value)[0];
}
