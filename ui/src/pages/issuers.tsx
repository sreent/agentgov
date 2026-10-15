// Who and what can use AgentGov, card by card: the people who sign in with single sign-on,
// the roles given to them in AgentGov, API keys, and agents' own identities (the identity
// issuers whose tokens agents authenticate with); and what can be done to each.

import type { ReactNode } from 'react';
import { ask, type Field } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Card, Chip, Copyable, EmptyState, Facts, PlainChip, TimeEl } from '../components/ui';
import { API_ROOT, api, getInfo } from '../lib/api';
import { fmt, fullFmt, plural } from '../lib/format';
import { formatLabels, orNull, parseLabels } from '../lib/forms';
import { refresh } from '../lib/router';
import { can, getMe, roleName } from '../lib/session';
import { NAME_HINT } from '../lib/shared';

type Issuer = any;
type Person = any;
type Grant = any;
type ApiKey = any;

/* ------------------------------------------------- agents' own identities */

// Identity issuers by kind: name, a subject its tokens carry, and its issuer.
export const ISSUER_KINDS: Record<string, [name: string, subject: string, issuer: string]> = {
  kubernetes: ['Kubernetes', 'system:serviceaccount:agents:support-bot', 'https://kubernetes.default.svc.cluster.local'],
  spiffe: ['SPIFFE', 'spiffe://example.org/ns/agents/sa/support-bot', 'spiffe://example.org'],
  oidc: ['OpenID Connect', '6f1c5e1a-…', 'https://login.microsoftonline.com/<tenant>/v2.0'],
};
export const ISSUER_KEYS_HINT: Record<string, string> = {
  kubernetes: "The cluster's issuer discovery URL, when Keycloak, or AgentGov for the gateway, can't read its keys at the issuer itself. Empty: at the issuer (for Keycloak's own cluster, with Keycloak's service account).",
  spiffe: 'The SPIFFE bundle endpoint (from SPIRE, say) with the trust domain\'s keys.',
  oidc: "The JWKS URL. Empty: found from the issuer's discovery document.",
};

export const issuerKind = (kind: string): string => (ISSUER_KINDS[kind] || [kind])[0];

// Microsoft Entra ID, whose app-only tokens name an agent identity by its object ID
// (v2 tokens' issuer, or v1's).
export const isEntra = (issuer: { issuer?: string } | null | undefined): boolean =>
  /^https:\/\/(login\.microsoftonline\.(com|us)|sts\.windows\.net)\//.test(issuer?.issuer || '');

function issuerSync(i: Issuer): ReactNode {
  if (i.sync?.error) {
    return (
      <>
        <PlainChip text="Out of sync" tone="critical" iconName="octagon" title={i.sync.error} />
        <div className="cell-sub break">{i.sync.error}</div>
      </>
    );
  }
  if (i.sync?.synced_at) return <><PlainChip text="Synced" tone="good" iconName="check-circle" /><div className="cell-sub"><TimeEl iso={i.sync.synced_at} /></div></>;
  return <span className="muted" title="Keycloak gets it within seconds when the control plane is connected to it">Not yet</span>;
}

// Whether the gateway takes an issuer's tokens itself (docs/agent-identity.md#straight-to-the-gateway).
function issuerGateway(i: Issuer): ReactNode {
  const g = i.gateway || {};
  if (!g.trusted) return <span className="muted" title="Its agents get AgentGov's tokens from Keycloak">Through Keycloak</span>;
  if (g.error && !g.keys) {
    return (
      <>
        <PlainChip text="Can't take tokens" tone="critical" iconName="octagon" title={g.error} />
        <div className="cell-sub break">{g.error}</div>
      </>
    );
  }
  if (!g.keys) return <span className="muted" title="AgentGov fetches them within seconds">Fetching its keys</span>;
  const taking = g.taking
    ? <PlainChip text="Takes its tokens" tone="good" iconName="check-circle" title={`With ${plural(g.keys, 'key')} AgentGov fetched from it`} />
    : i.status === 'blocked'
      ? <PlainChip text="Not while blocked" tone="warning" iconName="ban" />
      : <PlainChip text="Not while agents' own identities are off" tone="warning" iconName="power" />;
  return (
    <>
      {taking}
      <div className="cell-sub">{plural(g.keys, 'key')}{g.keys_at ? <>{' · '}<TimeEl iso={g.keys_at} /></> : null}</div>
      {g.error ? <div className="cell-sub break">{`Last fetch failed: ${g.error}`}</div> : null}
    </>
  );
}

const actionsHead = (t: string) => t || <span className="sr-only">Actions</span>;

// keycloak: whether AgentGov sets agents up in Keycloak; without it, the gateway alone
// takes issuers' tokens.
export function IssuersCard({ issuers, keycloak }: { issuers: Issuer[]; keycloak: boolean }) {
  const columns = ['Issuer', 'Status', 'Agents', keycloak ? 'In Keycloak' : null, 'At the gateway', ''].filter((t) => t !== null) as string[];
  const body = issuers.length ? (
    <div className="table-wrap">
      <table className="data rtable">
        <caption className="sr-only">Identity issuers</caption>
        <thead><tr>{columns.map((t, n) => <th key={n} scope="col" className={t === 'Agents' ? 'num' : undefined}>{actionsHead(t)}</th>)}</tr></thead>
        <tbody>
          {issuers.map((i) => (
            <tr key={i.name} data-issuer={i.name}>
              <td data-label="Issuer" className="break">
                <span className="cell-title">{i.name}</span>
                <div className="cell-sub">{`${issuerKind(i.kind)}: `}<code>{i.issuer}</code></div>
                {i.audience ? <div className="cell-sub">{'Audience: '}<code>{i.audience}</code></div> : null}
                {i.description ? <div className="cell-sub">{i.description}</div> : null}
              </td>
              <td data-label="Status"><Chip kind="server" value={i.status} /></td>
              <td data-label="Agents" className="num">{fmt(i.agents || 0)}</td>
              {keycloak ? <td data-label="In Keycloak">{issuerSync(i)}</td> : null}
              <td data-label="At the gateway">{issuerGateway(i)}</td>
              <td data-label="">
                {can('contain') ? (
                  <div className="btn-row">
                    {can('admin') ? <button type="button" className="btn btn--sm" onClick={guarded(() => issuerForm(i))}><Icon name="edit" />Edit</button> : null}
                    {can('admin') && i.gateway?.trusted ? (
                      <button type="button" className="btn btn--sm" title="Fetch its signing keys for the gateway now" onClick={guarded(() => fetchIssuerKeys(i))}>
                        <Icon name="refresh" />Fetch keys
                      </button>
                    ) : null}
                    <button type="button" className="btn btn--sm" onClick={guarded(() => blockIssuer(i))}>
                      <Icon name={i.status === 'blocked' ? 'undo' : 'ban'} />{i.status === 'blocked' ? 'Unblock' : 'Block'}
                    </button>
                    {can('admin') ? <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => deleteIssuer(i))}><Icon name="trash" />Delete</button> : null}
                  </div>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <EmptyState
      title="No identity issuers"
      text="Add one, and agents can authenticate with an identity they already have, such as a Kubernetes service account, a SPIFFE ID or a Microsoft Entra Agent ID, instead of a client secret."
    />
  );
  return (
    <Card
      title="Agent identity issuers"
      sub={keycloak
        ? "Agents that run where they already have an identity authenticate with their issuer's tokens: there's no secret to store, leak or rotate. Keycloak trades them for AgentGov's tokens; an issuer the gateway trusts has its tokens taken there too. Blocking an issuer stops all of its agents authenticating."
        : "Agents that run where they already have an identity call the gateway with their issuer's tokens, where it trusts the issuer: there's no secret to store, leak or rotate. Blocking an issuer stops all of its agents authenticating."}
      actions={can('admin') ? [
        <button key="add" type="button" className="btn btn--sm btn--primary" onClick={guarded(() => issuerForm(null))}><Icon name="plus" />Add issuer</button>,
      ] : null}
      flush={issuers.length > 0}
    >
      {body}
    </Card>
  );
}

async function issuerForm(i: Issuer | null) {
  const editing = Boolean(i);
  const oidcOnly = (field: Field): Field | null => (!editing || i.kind === 'oidc' ? field : null);
  const info = await getInfo();
  // The audience of the tokens agents call the gateway with themselves: its address.
  const audience = info?.issuer_audience || info?.audience || 'agentgov-gateway';
  const gatewayHint = (kind: string) => (kind === 'oidc'
    ? `Agents then call the gateway with their own token, without Keycloak: one for the audience above, else ${audience}. AgentGov fetches the issuer's keys for the gateway.`
    : `Agents then call the gateway with their own service account token, without Keycloak: a projected one for the audience ${audience}. AgentGov fetches the cluster's keys for the gateway.`);
  // A new issuer's form follows its kind. SPIFFE's JWT-SVIDs reach the gateway as
  // AgentGov's tokens, through Keycloak: the gateway's box is hidden for them, its hint left
  // as it was.
  let gatewayKind = 'kubernetes';
  const saved = await ask<Issuer>({
    title: editing ? `Edit ${i.name}` : 'Add an identity issuer',
    text: editing
      ? `A ${issuerKind(i.kind)} issuer. The change takes effect within seconds; it is recorded in the evidence ledger.`
      : info?.identity_provider
        ? "AgentGov makes it an identity provider in Keycloak. Each agent then names its subject there, and authenticates with the issuer's token for that subject."
        : "Each agent then names its subject there, and calls the gateway with the issuer's token for that subject, once the gateway takes the issuer's tokens.",
    iconName: editing ? 'edit' : 'key', confirm: editing ? 'Save changes' : 'Add issuer', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'prod-cluster', hint: NAME_HINT },
      editing ? null : {
        id: 'kind', label: 'Kind', type: 'select', value: 'kubernetes', options: [
          { value: 'kubernetes', label: "Kubernetes: its pods' service account tokens" },
          { value: 'spiffe', label: 'SPIFFE: JWT-SVIDs, from SPIRE say' },
          { value: 'oidc', label: 'OpenID Connect: Microsoft Entra ID (Agent ID), Okta, AWS, Google, GitHub Actions…' },
        ],
      },
      {
        id: 'issuer', label: 'Issuer', required: true, mono: true, value: i?.issuer || '',
        placeholder: editing ? ISSUER_KINDS[i.kind || 'kubernetes'][2] : (v) => ISSUER_KINDS[v.kind][2],
        hint: 'As its tokens name it (their iss claim). For SPIFFE, the trust domain.',
      },
      {
        id: 'keys_url', label: 'Keys URL', mono: true, value: i?.keys_url || '',
        hint: editing ? ISSUER_KEYS_HINT[i.kind || 'kubernetes'] : (v) => ISSUER_KEYS_HINT[v.kind],
      },
      oidcOnly({
        id: 'audience', label: 'Audience', mono: true, value: i?.audience || '', placeholder: 'api://agentgov',
        hint: "Only when its tokens can't carry Keycloak's realm URL as their audience: the one they carry. Microsoft Entra ID's name an app, such as api://agentgov.",
        hidden: editing ? undefined : (v) => v.kind !== 'oidc',
      }),
      oidcOnly({
        id: 'allow_reuse', label: 'A token may authenticate more than once', type: 'checkbox', value: i?.allow_reuse || false,
        hint: "Otherwise Keycloak takes each token once, so a stolen one is worth less. Tokens without a jti claim, such as Microsoft Entra ID's, need it.",
        hidden: editing ? undefined : (v) => v.kind !== 'oidc',
      }),
      editing && i.kind === 'spiffe' ? null : {
        id: 'gateway', label: 'The gateway takes its tokens itself', type: 'checkbox', value: i?.gateway?.trusted || false,
        hint: editing ? gatewayHint(i.kind || 'kubernetes') : (v) => {
          if (v.kind !== 'spiffe') gatewayKind = v.kind;
          return gatewayHint(gatewayKind);
        },
        hidden: editing ? undefined : (v) => v.kind === 'spiffe',
      },
      { id: 'description', label: 'Description', type: 'textarea', value: i?.description || '' },
      { id: 'labels', label: 'Labels', value: formatLabels(i?.labels), placeholder: 'env=prod', mono: true },
    ],
    submit: (v) => {
      const kind = editing ? i.kind : v.kind;
      const body = {
        issuer: v.issuer, keys_url: orNull(v.keys_url), description: v.description, labels: parseLabels(v.labels),
        ...(kind === 'oidc' ? { audience: orNull(v.audience), allow_reuse: v.allow_reuse } : {}),
        ...(kind !== 'spiffe' ? { gateway: Boolean(v.gateway) } : {}),
      };
      if (editing) return api(`v1/identity-issuers/${encodeURIComponent(i.name)}`, { method: 'PATCH', body, ifMatch: i.version });
      return api('v1/identity-issuers', { method: 'POST', body: { name: v.name, kind, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}. Give agents a workload identity from it on their edit form.`);
  const g = saved.gateway || {};
  if (g.trusted && g.error) toast(`The gateway can't take ${saved.name}'s tokens yet: ${g.error}`, { tone: 'critical' });
  await refresh();
}

async function blockIssuer(i: Issuer) {
  const block = i.status !== 'blocked';
  const stops: string[] = [];
  if ((await getInfo())?.identity_provider) stops.push(`Keycloak stops taking its tokens within seconds, so ${plural(i.agents || 0, 'agent')} can't get a new access token; the ones they have expire within minutes.`);
  if (i.gateway?.trusted) stops.push("The gateway stops taking its tokens within seconds: calls with them come from callers AgentGov can't tell, refused unless unknown callers are only monitored.");
  const done = await ask({
    title: block ? `Block ${i.name}?` : `Unblock ${i.name}?`,
    text: block
      ? stops.join(' ') || `${plural(i.agents || 0, 'agent')} can't authenticate with its tokens.`
      : 'Its agents can authenticate with its tokens again.',
    tone: block ? 'danger' : 'primary', iconName: block ? 'ban' : 'undo', confirm: block ? 'Block' : 'Unblock',
    submit: () => api(`v1/identity-issuers/${encodeURIComponent(i.name)}/${block ? 'block' : 'unblock'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(block ? `Blocked ${i.name}.` : `Unblocked ${i.name}.`);
  await refresh();
}

// Fetch the keys of an issuer the gateway trusts now, as when it rotated them early.
async function fetchIssuerKeys(i: Issuer) {
  let saved;
  try {
    saved = await api(`v1/identity-issuers/${encodeURIComponent(i.name)}/keys`, { method: 'POST' });
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
    return;
  }
  const g = saved.gateway || {};
  if (g.error) toast(`Couldn't fetch ${saved.name}'s keys: ${g.error}`, { tone: 'critical' });
  else toast(`Fetched ${plural(g.keys, 'key')} from ${saved.name}.`);
  await refresh();
}

async function deleteIssuer(i: Issuer) {
  const done = await ask({
    title: `Delete ${i.name}?`,
    text: i.agents
      ? `${plural(i.agents, 'agent')} authenticate with it. Give them another identity, or a client secret, first.`
      : 'Its identity provider goes from Keycloak too.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete issuer', busy: 'Deleting…',
    submit: () => api(`v1/identity-issuers/${encodeURIComponent(i.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${i.name}.`);
  await refresh();
}

/* ----------------------------------------------------------- people, roles */

export function SignInsCard({ view }: { view: any }) {
  const people: Person[] = view.people || [];
  const signedIn = people.filter((p) => p.status === 'signed_in').length;
  let body: ReactNode;
  if (!people.length) {
    body = view.sso_enabled
      ? <EmptyState title="Nobody has signed in yet" text="People appear here after their first sign-in with single sign-on." />
      : <EmptyState title="Single sign-on is not set up" text="People sign in with API keys until an identity provider is connected." />;
  } else {
    body = (
      <div className="table-wrap">
        <table className="data rtable">
          <caption className="sr-only">People</caption>
          <thead><tr>{['Person', 'Roles', 'Status', 'Last sign-in', 'Sign-ins', ''].map((t, n) => <th key={n} scope="col">{actionsHead(t)}</th>)}</tr></thead>
          <tbody>
            {people.map((person) => (
              <tr key={person.subject}>
                <td data-label="Person" className="break">
                  <span className="cell-title">{person.name}</span>
                  <div className="cell-sub" title="Subject at the identity provider">{person.subject}</div>
                </td>
                <td data-label="Roles">
                  {person.roles.length
                    ? <div className="chip-row">{person.roles.map((r: string, n: number) => <PlainChip key={n} text={roleName(r)} />)}</div>
                    : <span className="muted">None</span>}
                </td>
                <td data-label="Status">
                  <Chip kind="person" value={person.status} title={person.status === 'refused' ? 'Refused at the last attempt: no AgentGov role' : null} />
                  {person.status === 'signed_in'
                    ? <div className="cell-sub">{`${plural(person.active_sessions, 'session')} until `}<TimeEl iso={person.session_expires_at} absolute /></div>
                    : person.status === 'refused' ? <div className="cell-sub">{'tried '}<TimeEl iso={person.last_refused} /></div> : null}
                </td>
                <td data-label="Last sign-in" className="nowrap"><TimeEl iso={person.last_sign_in} empty="Never" /></td>
                <td data-label="Sign-ins" className="num">{fmt(person.sign_ins)}</td>
                <td data-label="">
                  {can('admin') && person.active_sessions
                    ? <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => signPersonOut(person)}><Icon name="signout" />Sign out</button>
                    : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <Card
      title="People"
      sub={<>
        {`${plural(signedIn, 'person', 'people')} signed in now. Roles come from the identity provider at each sign-in, and from those given below: to take someone's access away, remove their role there, then sign them out here.`}
        {view.provider ? <span style={{ display: 'block', marginTop: 4 }}>{providerSummary(view.provider)}</span> : null}
      </>}
      flush={people.length > 0}
    >
      {body}
    </Card>
  );
}

// What people sign in with, as AgentGov reads it.
const PROVIDER_NAMES: Record<string, string> = { keycloak: 'Keycloak', entra: 'Microsoft Entra ID', google: 'Google', oidc: 'OpenID Connect' };

function providerSummary(p: any): string {
  const roles = p.role_map?.length
    ? ` Roles from ${p.roles_claims.join(', ')}: ${p.role_map.map((m: any) => `${m.value} → ${roleName(m.role)}`).join('; ')}.`
    : ` Roles from ${p.roles_claims.join(', ')}, named ${p.role_prefix}admin, ${p.role_prefix}approver and so on, or ${p.role_prefix}approver@sales for one team's agents.`;
  const domains = p.allowed_domains?.length ? ` Only ${p.allowed_domains.join(', ')} may sign in.` : '';
  // Someone it signs in with no role given to them.
  const others = p.without_role === 'person'
    ? ' Anyone else it signs in sees only the issues and requests sent to them.'
    : p.require_role
      ? ' Only people with a role may sign in: give the person role to those who should see only what is sent to them.'
      : ' People without a role are refused.';
  return `Signing in with ${PROVIDER_NAMES[p.kind] || p.kind}: ${p.issuer}.${roles}${domains}${others}`;
}

export function RoleGrantsCard({ view }: { view: any }) {
  if (!view.sso_enabled) return null;
  const grants: Grant[] = view.grants || [];
  return (
    <Card
      title="Roles given in AgentGov"
      sub="Roles usually come from the identity provider. Give one here when its tokens carry no groups (Google's do not), or to the first administrators: it applies from the person's next sign-in with this email address, beside the provider's."
      actions={can('admin') ? [
        <button key="give" type="button" className="btn btn--sm btn--primary" onClick={guarded(giveRole)}><Icon name="plus" />Give a role</button>,
      ] : null}
      flush={grants.length > 0}
    >
      {grants.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">Roles given in AgentGov</caption>
            <thead><tr>{['Person', 'Role', 'Given by', 'When', ''].map((t, n) => <th key={n} scope="col">{actionsHead(t)}</th>)}</tr></thead>
            <tbody>
              {grants.map((g) => (
                <tr key={`${g.email}/${g.role}`} data-grant={`${g.email}/${g.role}`}>
                  <td data-label="Person" className="break">
                    <span className="cell-title">{g.email}</span>
                    {g.reason ? <div className="cell-sub">{g.reason}</div> : null}
                  </td>
                  <td data-label="Role"><PlainChip text={roleName(g.role)} /></td>
                  <td data-label="Given by" className="break">{g.granted_by}</td>
                  <td data-label="When" className="nowrap"><TimeEl iso={g.granted_at} /></td>
                  <td data-label="">
                    {can('admin')
                      ? <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => takeRole(g)}><Icon name="trash" />Take away</button>
                      : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="No roles given here" text="Everyone's roles come from the identity provider." />
      )}
    </Card>
  );
}

// Whom a role is for: every team, or one team's agents only (approver@sales).
function teamField(teams: any[]): Field | null {
  if (!teams.length) return null;
  return {
    id: 'team', label: 'For', type: 'select', value: '',
    options: [{ value: '', label: 'Every team' }, ...teams.map((t) => ({ value: t.name, label: `Only the agents of team ${t.name}` }))],
    hint: "For one team: its agents, and their issues, approvals and ledger entries; nothing organisation-wide. An agent's team is its own, else its blueprint's, else the default team.",
  };
}

async function giveRole() {
  const teams = await api<any[]>('v1/teams').catch(() => []);
  const saved = await ask<Grant>({
    title: 'Give a role',
    text: 'The person gets it the next time they sign in, with this email address, which the identity provider vouches for. It is recorded in the evidence ledger.',
    iconName: 'key', confirm: 'Give role',
    fields: [
      { id: 'email', label: 'Email address', required: true, placeholder: 'alice@example.com' },
      {
        id: 'role', label: 'Role', type: 'select', value: 'auditor', required: true, options: [
          { value: 'admin', label: 'Admin: everything' },
          { value: 'approver', label: 'Approver: decide approvals and issues' },
          { value: 'secops', label: 'Security operations: triage and contain' },
          { value: 'auditor', label: 'Auditor: read everything, change nothing' },
          { value: 'registrar', label: 'Registrar: register agents and tool servers' },
          { value: 'person', label: 'Person: only the issues and requests sent to them' },
        ],
      },
      teamField(teams),
      { id: 'reason', label: 'Why', type: 'textarea', hint: 'For the evidence ledger.' },
    ],
    submit: (v) => api('v1/access/grants', { method: 'POST', body: { email: v.email, role: v.role, team: orNull(v.team), reason: orNull(v.reason) } }),
  });
  if (!saved) return;
  toast(`Gave ${saved.email} the role ${roleName(saved.role)}, from their next sign-in.`);
  await refresh();
}

async function takeRole(g: Grant) {
  const done = await ask<any>({
    title: `Take ${roleName(g.role)} away from ${g.email}?`,
    text: 'Their sessions end now. When they sign in again, they have only the roles the identity provider gives them.',
    tone: 'danger', iconName: 'trash', confirm: 'Take away', busy: 'Taking away…',
    submit: () => api(`v1/access/grants/${encodeURIComponent(g.email)}/${encodeURIComponent(g.role)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Took ${roleName(g.role)} away from ${g.email} (${plural(done.ended, 'session')} ended).`);
  await refresh();
}

async function signPersonOut(person: Person) {
  const me = getMe();
  const self = me?.via === 'session' && me?.name === person.name;
  const done = await ask<any>({
    title: `Sign ${person.name} out?`,
    text: `This ends ${plural(person.active_sessions, 'session')}${self ? ', including yours' : ''}. A new sign-in reads their roles from the identity provider again, so it only succeeds if they still have an AgentGov role.`,
    tone: 'danger', iconName: 'signout', confirm: 'Sign out', busy: 'Signing out…',
    submit: () => api(`v1/access/people/${encodeURIComponent(person.subject)}/sign-out`, { method: 'POST' }),
  });
  if (!done) return;
  toast(`Signed ${person.name} out (${plural(done.ended, 'session')} ended).`);
  await refresh();
}

/* ----------------------------------------------------------------- API keys */

const KEY_ROLES = [
  ['auditor', 'Auditor: reads everything, including the ledger, and changes nothing'],
  ['approver', 'Approver: reads everything and decides approval requests and issues'],
  ['secops', "Security operations: the security team's SIEM or SOAR. Reads everything, and does what the hand-off to security operations allows"],
  ['registrar', 'Registrar: registers agents and tool servers for review (CI pipelines, developers)'],
  ['admin', 'Admin: everything'],
  ['service', 'Service: internal components such as OPA and the governance processor'],
];

// How long a key works, as its creator chooses: days, or never (where keys may).
const KEY_DAYS = [30, 90, 180, 365];

export function ApiKeysCard({ keys, policy }: { keys: ApiKey[]; policy: any }) {
  const active = keys.filter((k) => k.status === 'active').length;
  const expired = keys.filter((k) => k.status === 'expired').length;
  const revoked = keys.filter((k) => k.status === 'revoked').length;
  const counts = [plural(active, 'active key'), expired ? `${fmt(expired)} expired` : null, revoked ? `${fmt(revoked)} revoked` : null].filter(Boolean).join(', ');
  const lasting = policy.max_days ? ` Keys work for ${plural(policy.max_days, 'day')} at most.` : '';
  return (
    <Card
      title="API keys"
      sub={`${counts}. Requests made with a key are recorded in the ledger as <role>:<name>.${lasting} A key in use warns its users two weeks before it expires.`}
      actions={can('admin') ? [
        <button key="create" type="button" className="btn btn--sm btn--primary" onClick={guarded(() => createApiKey(policy))}><Icon name="plus" />Create API key</button>,
      ] : null}
      flush={keys.length > 0}
    >
      {keys.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">API keys</caption>
            <thead><tr>{['Name', 'Role', 'Key', 'Created', 'Last used', 'Expires', 'Status', ''].map((t, n) => <th key={n} scope="col">{actionsHead(t)}</th>)}</tr></thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td data-label="Name" className="break"><span className="cell-title">{k.name}</span></td>
                  <td data-label="Role">{roleName(k.role)}</td>
                  <td data-label="Key"><code title="The first characters of the key">{`${k.prefix}…`}</code></td>
                  <td data-label="Created" className="nowrap"><TimeEl iso={k.created_at} /></td>
                  <td data-label="Last used" className="nowrap"><TimeEl iso={k.last_used_at} empty="Never" /></td>
                  <td data-label="Expires" className="nowrap">{k.status === 'revoked' ? <span className="muted">—</span> : <TimeEl iso={k.expires_at} empty="Never" />}</td>
                  <td data-label="Status">
                    <Chip kind="apikey" value={k.status}
                      title={k.revoked_at ? `Revoked ${fullFmt.format(new Date(k.revoked_at))}` : k.status === 'expired' ? `Expired ${fullFmt.format(new Date(k.expires_at))}` : null} />
                  </td>
                  <td data-label="">
                    {k.status !== 'revoked' && can('admin')
                      ? <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => revokeApiKey(k)}><Icon name="ban" />Revoke</button>
                      : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="No API keys" text="Until you create role-scoped keys, the CLI and automation need the bootstrap admin token." />
      )}
    </Card>
  );
}

async function createApiKey(policy: any) {
  const max = policy.max_days || 0;
  const choices = [...new Set([...KEY_DAYS, policy.default_days || 90])].filter((d) => !max || d <= max).sort((a, b) => a - b);
  const expiries = [...choices.map((d) => ({ value: String(d), label: d % 365 === 0 ? plural(d / 365, 'year') : plural(d, 'day') })),
    ...(max ? [] : [{ value: 'never', label: 'Never (until it is revoked)' }])];
  const teams = await api<any[]>('v1/teams').catch(() => []);
  const created = await ask<ApiKey>({
    title: 'Create an API key',
    text: 'The key is shown once, right after it is created. The control plane keeps only a hash of it.',
    iconName: 'key', confirm: 'Create key', busy: 'Creating…',
    fields: [
      { id: 'name', label: 'Name', required: true, placeholder: 'ci-pipeline', hint: 'Who or what uses the key. Approver keys named after a sponsor can attest that sponsor\'s agents.' },
      { id: 'role', label: 'Role', type: 'select', value: 'auditor', options: KEY_ROLES.map(([value, label]) => ({ value, label })) },
      teamField(teams),
      { id: 'expires', label: 'Expires after', type: 'select', value: String(policy.default_days || 90), options: expiries, hint: 'Requests made with it are refused after that. Two weeks before, if it is in use, an issue says so.' },
    ],
    submit: (v) => api('v1/apikeys', { method: 'POST', body: { name: v.name, role: v.role, team: orNull(v.team), expires_in_days: v.expires === 'never' ? null : Number(v.expires) } }),
  });
  if (!created) return;
  const base = API_ROOT.href.replace(/\/$/, '');
  await ask({
    title: `API key for ${created.name}`,
    text: "Copy the key now: it can't be shown again. If it is lost, revoke it and create another.",
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: (
      <div className="stack" style={{ gap: 12 }}>
        <Facts rows={[
          ['Key', <Copyable text={created.token} label="API key" />], ['Role', roleName(created.role)],
          ['Expires', created.expires_at ? <TimeEl iso={created.expires_at} absolute /> : 'Never'],
        ]} />
        <div className="stack" style={{ gap: 6 }}>
          <span className="field-label">Use it with the CLI</span>
          <pre className="kv-pre">{`export AGENTGOV_URL=${base}\nexport AGENTGOV_TOKEN=${created.token}\nagentgov whoami`}</pre>
        </div>
      </div>
    ),
  });
  await refresh();
}

async function revokeApiKey(k: ApiKey) {
  const me = getMe();
  const own = me?.via === 'api_key' && me?.name === k.name && me?.role === k.role;
  const done = await ask({
    title: `Revoke ${k.name}?`,
    text: `Requests made with this key are refused from now on. Revoked keys stay listed for the record.${own ? ' You are signed in with this key, so you will be signed out.' : ''}`,
    tone: 'danger', iconName: 'ban', confirm: 'Revoke key', busy: 'Revoking…',
    submit: () => api(`v1/apikeys/${encodeURIComponent(k.id)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Revoked ${k.name}.`);
  await refresh();
}
