// Who is signed in, and what they may do here. The control plane enforces roles; this only
// hides controls it would refuse.

import { humanize } from './format';
import { readStore, writeStore } from './storage';

const TOKEN_KEY = 'agentgov.token';

/** Who is signed in (GET /v1/me, or GET /auth/session for single sign-on). */
export interface Me {
  actor: string;
  name?: string;
  role?: string;
  roles: string[];
  // The roles held for some teams only, and those teams: {approver: ['sales']}.
  teams?: Record<string, string[]>;
  via?: string;
  handoff?: { reached?: string[] };
  inbox?: { issues?: boolean; approvals?: boolean };
  signed_in?: boolean;
  [key: string]: unknown;
}

// An API token kept in this tab, or nothing: signed in through single sign-on, the control
// plane keeps the session and the browser holds only an HttpOnly cookie.
let token: string | null = readStore('sessionStorage', TOKEN_KEY);
let session = false;
let me: Me | null = null;

export const getToken = (): string | null => token;
export const inSession = (): boolean => session;
export const getMe = (): Me | null => me;

/** Use this token for the API's calls (while signing in, before it is known to work). */
export function setToken(value: string | null): void {
  token = value;
}

/** Signed in: as `who`, with the token kept in this tab, or by single sign-on. */
export function signedIn(who: Me, { keepToken }: { keepToken: boolean }): void {
  me = who;
  session = who.via === 'session';
  if (keepToken && token) writeStore('sessionStorage', TOKEN_KEY, token);
}

export function signedOut(): void {
  token = null;
  session = false;
  me = null;
  writeStore('sessionStorage', TOKEN_KEY, null);
}

export const READ_ROLES = ['admin', 'approver', 'secops', 'auditor'];

// What the signed-in person may change. The security team's secops role may triage, contain
// and decide as far as the hand-off to security operations has reached. About an agent (or
// its issue, request or access), by the roles they hold where it is: its your_roles, when
// some of their roles are for some teams only (approver@sales).
export function can(kind: string, where?: { your_roles?: string[] } | null): boolean {
  const roles = where?.your_roles || me?.roles || [];
  if (roles.includes('admin')) return true;
  if (kind === 'approve' && roles.includes('approver')) return true;
  return roles.includes('secops') && (me?.handoff?.reached || []).includes(kind);
}

// The roles held for some teams only, and those teams: {approver: ['sales']}.
export function teamRoles(): Record<string, string[]> {
  return me?.teams || {};
}

// Whether they may do this anywhere: for every team, or for one of theirs.
export function canSome(kind: string): boolean {
  return can(kind) || can(kind, { your_roles: Object.keys(teamRoles()) });
}

// Someone whose roles are all for some teams only: they have those teams' agents, and their
// issues, approvals and ledger entries (docs/administration.md#roles-for-one-team).
export function isScoped(): boolean {
  return Boolean(me) && !me!.roles.some((r) => READ_ROLES.includes(r))
    && Object.keys(teamRoles()).some((r) => READ_ROLES.includes(r));
}
export const TEAM_PAGES = ['agents', 'findings', 'approvals', 'ledger'];

// A role as people read it: "Approver", or "Approver for sales" for one team's agents.
const ROLE_NAMES: Record<string, string> = { secops: 'Security operations' };
export function roleName(value: string | null | undefined): string {
  const [role, team] = String(value || '').split('@');
  const name = ROLE_NAMES[role] || humanize(role);
  return team ? `${name} for ${team}` : name;
}

// Who may open the admin center: a role that reads, for every team or for some, or the
// person role.
export function mayOpen(who: Me): boolean {
  return who.roles.some((r) => READ_ROLES.includes(r) || r === 'person')
    || Object.keys(who.teams || {}).some((r) => READ_ROLES.includes(r));
}

// Someone without an AgentGov role, signed in to see the issues sent to them (the issues
// feature) and decide the approval requests that agents acting for them sent them (the
// approvals-by-person feature). They see only those.
export function isPerson(): boolean {
  return Boolean(me) && !me!.roles.some((r) => READ_ROLES.includes(r)) && me!.roles.includes('person');
}

// Their pages: issues (on the findings page) and approvals, as the features allow.
export function personPages(): string[] {
  const inbox = me?.inbox || {};
  const pages = [inbox.issues ? 'findings' : null, inbox.approvals ? 'approvals' : null].filter(Boolean) as string[];
  return pages.length ? pages : ['approvals'];
}

export function personHome(): string {
  return `#/${personPages()[0]}`;
}

// Auditors, and no other role: they read reports, so their first page is Compliance.
export function isAuditor(): boolean {
  const roles = me?.roles || [];
  return roles.includes('auditor') && !roles.some((r) => ['admin', 'approver', 'secops'].includes(r));
}

// The page someone starts on, by what they do here.
export function home(): string {
  if (isPerson()) return personHome();
  if (isScoped()) return '#/agents';
  return isAuditor() ? '#/ledger/compliance' : '#/overview';
}

// Reasons /auth/callback sends back (?sso_error=...). Only these fixed texts are shown.
export const SSO_ERRORS: Record<string, string> = {
  no_role: 'You signed in, but your account has no AgentGov role. Ask an administrator to give you one.',
  domain: "Your account isn't from an organisation allowed to sign in to AgentGov. Sign in with your work account.",
  state: 'That sign-in could not be completed in this browser. Start again.',
  expired: 'That sign-in expired or was already used. Start again.',
  provider: 'The identity provider could not complete the sign-in. Try again, or use an API token.',
  token: "The control plane could not verify the identity provider's response. Try again, or ask an administrator to check the single sign-on settings.",
};
