// Policies: the blueprints agents are registered on, access packages they hold for a while,
// management rules, and organisation Rego policies; and what OPA would decide for a call.

import { useState, type ReactNode } from 'react';
import { ask, type Values } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Card, EmptyState, Facts, PageHead, PlainChip, RefreshButton } from '../components/ui';
import { api, saveDownload } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { countBy, fileStamp, fmt, fmtBytes, humanize, plural } from '../lib/format';
import {
  formatGrants, formatLabels, formatModelAccess, parseBudget, parseGrants, parseLabels, parseList, parseModelAccess,
} from '../lib/forms';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { featureModes, NAME_HINT, RISK_TIERS } from '../lib/shared';
import { statusMeta, toneOf } from '../lib/status';
import { PolicyCard, WhatIfCard } from './accessPackages';
import { RuleCard, ruleForm, RulesNote, runRules } from './rules';

interface PoliciesData {
  blueprints: any[];
  policies: any[];
  agents: any[];
  servers: any[];
  providers: any[];
  packages: any[];
  rules: any[];
  modes: Record<string, string>;
}

export const policiesPage: PageDef<PoliciesData> = {
  re: /^\/policies$/,
  nav: 'policies',
  title: 'Policies',
  load: async () => {
    const [blueprints, policies, agents, servers, providers, packages, rules, modes] = await Promise.all([
      api('v1/blueprints'), api('v1/policies'), api('v1/agents'), api('v1/toolservers'), api('v1/models/providers'),
      api('v1/access-packages').catch(() => []), api('v1/rules').catch(() => []), featureModes().catch(() => ({})),
    ]);
    return { blueprints, policies, agents, servers, providers, packages, rules, modes };
  },
  View: PoliciesView,
};

function PoliciesView({ data }: { data: PoliciesData }) {
  const { blueprints, policies, agents, servers, providers, packages, rules, modes } = data;
  const [exporting, setExporting] = useState(false);
  const usage = countBy(agents, (a) => a.blueprint || '');
  const exportManifests = async () => {
    setExporting(true);
    try {
      const blob = await saveDownload('v1/export', `agentgov-manifests-${fileStamp()}.yaml`);
      toast(`Exported the registry as YAML manifests (${fmtBytes(blob.size)}).`);
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    } finally {
      setExporting(false);
    }
  };
  const admin = can('admin');
  const sectionAction = (label: string, onClick: () => unknown) => (admin
    ? <button type="button" className="btn btn--sm" onClick={guarded(onClick)}><Icon name="plus" />{label}</button>
    : null);
  return (
    <div className="page">
      <PageHead
        title="Policies"
        sub="Blueprints decide what each class of agent may call. Organisation Rego policies add rules on top of the built-in library, and OPA enforces both at the gateway."
        actions={[
          admin ? <button key="import" type="button" className="btn" onClick={guarded(importManifests)}><Icon name="upload" />Import manifests</button> : null,
          <button key="export" type="button" className="btn" disabled={exporting} onClick={exportManifests}><Icon name="download" />Export manifests</button>,
          <RefreshButton key="refresh" />,
        ]}
      />
      <div className="policy-layout">
        <div className="stack">
          <section className="stack" aria-labelledby="bp-title">
            <div className="section-title">
              <div><h2 id="bp-title">Blueprints</h2><p>IT-approved templates: permissions, risk tier, sponsor and review rules</p></div>
              {sectionAction('New blueprint', () => blueprintFormFlow(null, servers))}
            </div>
            {blueprints.length ? (
              <div className="bp-grid">{blueprints.map((b) => <BlueprintCard key={b.id} b={b} used={usage[b.name] || 0} servers={servers} />)}</div>
            ) : (
              <section className="card">
                <EmptyState title="No blueprints yet" text={admin ? 'Create one to give a class of agents its tools.' : 'An admin creates blueprints here, with the CLI or with a Blueprint manifest.'} />
              </section>
            )}
          </section>
          <section className="stack" aria-labelledby="pkg-title">
            <div className="section-title">
              <div>
                <h2 id="pkg-title">Access packages</h2>
                <p>Grants agents hold for a while once approved: asked for, reminded before they expire, renewed or reviewed</p>
              </div>
              {sectionAction('New package', () => packageForm(null, servers, blueprints))}
            </div>
            {packages.length ? (
              <div className="bp-grid">{packages.map((pk) => <PackageCard key={pk.id} pk={pk} servers={servers} blueprints={blueprints} />)}</div>
            ) : (
              <section className="card">
                <EmptyState title="No access packages" text={admin
                  ? 'Create one for access agents need for a while: a project, an incident, a pilot.'
                  : 'An admin creates access packages here, with the CLI or with an AccessPackage manifest.'} />
              </section>
            )}
          </section>
          <section className="stack" aria-labelledby="rules-title">
            <div className="section-title">
              <div>
                <h2 id="rules-title">Management rules</h2>
                <p>What to do about agents that meet some conditions for long enough, after telling their people</p>
              </div>
              {admin ? (
                <div className="btn-row">
                  {rules.length ? <button type="button" className="btn btn--sm" onClick={guarded(runRules)}><Icon name="refresh" />Run now</button> : null}
                  {sectionAction('New rule', () => ruleForm(null, blueprints))}
                </div>
              ) : null}
            </div>
            <RulesNote modes={modes} />
            {rules.length ? (
              <div className="bp-grid">{rules.map((r) => <RuleCard key={r.id} r={r} blueprints={blueprints} />)}</div>
            ) : (
              <section className="card">
                <EmptyState title="No management rules" text={admin
                  ? 'Add one to block agents nobody uses, give ownerless agents an owner, or clean up stale registrations, after telling their people.'
                  : 'An admin adds management rules here, with the CLI or with a ManagementRule manifest.'} />
              </section>
            )}
          </section>
          <section className="stack" aria-labelledby="rego-title">
            <div className="section-title">
              <div>
                <h2 id="rego-title">Organisation policies</h2>
                <p>Rego modules under agentgov.custom that can add denials, approval requirements and redactions</p>
              </div>
              {sectionAction('Add policy', () => policyFormFlow(null))}
            </div>
            {policies.length
              ? policies.map((p) => <PolicyCard key={p.id} p={p} />)
              : <section className="card"><EmptyState title="No organisation policies" text="Only the built-in library (package agentgov.mcp) is enforced." /></section>}
          </section>
        </div>
        <WhatIfCard agents={agents} servers={servers} providers={providers} />
      </div>
    </div>
  );
}

/** Create a blueprint (no `b`) or edit one. */
async function blueprintFormFlow(b: any, servers: any[]) {
  const editing = Boolean(b);
  const teams: any[] = await api('v1/teams').catch(() => []);
  const saved = await ask<any>({
    title: editing ? `Edit blueprint ${b.name}` : 'New blueprint',
    text: editing
      ? 'Every agent on this blueprint gets the change as soon as OPA loads the updated policy bundle.'
      : 'A blueprint grants tools to every agent that uses it and sets their sponsor and review rules.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save changes' : 'Create blueprint',
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'customer-support', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', value: b?.description || '' },
      {
        id: 'permissions', label: 'Tool grants', type: 'code', rows: 4, value: formatGrants(b?.permissions), placeholder: 'crm: search_customers, get_*',
        hint: `One server per line; tool names can use * wildcards, and * alone means every tool.${servers.length ? ` Registered servers: ${servers.map((ts) => ts.name).join(', ')}.` : ''}`,
      },
      {
        type: 'row',
        fields: [
          { id: 'risk_tier', label: 'Risk tier', type: 'select', value: b?.risk_tier || 'medium', options: RISK_TIERS.map((t) => ({ value: t, label: humanize(t) })) },
          { id: 'attestation_days', label: 'Review every (days)', type: 'number', min: 1, value: b ? (b.attestation_days ?? '') : '90', hint: 'Empty: no periodic review.' },
        ],
      },
      { id: 'require_sponsor', label: 'Require a sponsor before activation', type: 'checkbox', value: b ? b.require_sponsor : true },
      {
        id: 'require_workload_identity', label: 'Require a workload identity: no client secrets', type: 'checkbox', value: b ? b.require_workload_identity : false,
        hint: 'Its agents authenticate with an identity from an identity issuer (Access page) before they can be activated.',
      },
      { type: 'section', label: 'Models' },
      {
        id: 'model_access', label: 'Model access', type: 'code', rows: 2, value: formatModelAccess(b?.model_access), placeholder: 'openai: gpt-4o-mini, gpt-4.1*',
        hint: 'Models its agents may call through the gateway: one provider per line; model names can use * wildcards.',
      },
      { id: 'daily_token_budget', label: 'Daily token budget per agent', type: 'number', min: 0, value: b?.daily_token_budget ?? '', hint: 'Input and output tokens per UTC day. Empty: no budget.' },
      { type: 'section', label: 'Agent to agent' },
      {
        id: 'agent_access', label: 'Agents its agents may call', value: (b?.agent_access || []).join(', '), placeholder: 'billing-agent, kb-*', mono: true,
        hint: 'Over A2A, through the gateway: agent names separated by commas; names can use * wildcards. Empty: none.',
      },
      { type: 'section', label: 'People' },
      { id: 'acts_for', label: 'Its agents act for', type: 'select', value: b?.acts_for || 'either', options: Object.entries(ACTS_FOR).map(([value, label]) => ({ value, label })) },
      {
        id: 'people_groups', label: "People's groups", value: (b?.people_groups || []).join(', '), placeholder: 'support, /emea/sales', mono: true,
        hint: 'When its agents act for a person, the person must be in one of these groups. Empty: anyone.',
      },
      {
        id: 'approvals_by', label: 'Approval requests made for a person go to', type: 'select', value: b?.approvals_by || 'approvers', options: Object.entries(APPROVALS_BY).map(([value, label]) => ({ value, label })),
        hint: 'To the person while the approvals-by-person feature is on; administrators can always decide.',
      },
      {
        id: 'team', label: 'Team', type: 'select', value: b?.team || '',
        options: [{ value: '', label: 'The default team' }, ...teams.map((t) => ({ value: t.name, label: t.name }))],
        hint: 'Issues about its agents go to their owners, then their sponsors, then this team.',
      },
      { id: 'labels', label: 'Labels', value: formatLabels(b?.labels), placeholder: 'data=customer', mono: true },
    ],
    submit: (v) => {
      const days = v.attestation_days ? Number(v.attestation_days) : null;
      if (days !== null && !(Number.isInteger(days) && days > 0)) throw new Error('The review period must be a whole number of days, or empty.');
      const body = {
        description: v.description, permissions: parseGrants(v.permissions), risk_tier: v.risk_tier,
        attestation_days: days, require_sponsor: v.require_sponsor, labels: parseLabels(v.labels),
        require_workload_identity: v.require_workload_identity,
        model_access: parseModelAccess(v.model_access), daily_token_budget: parseBudget(v.daily_token_budget),
        agent_access: parseList(v.agent_access),
        acts_for: v.acts_for, people_groups: parseList(v.people_groups), approvals_by: v.approvals_by,
        team: v.team || null,
      };
      if (editing) return api(`v1/blueprints/${encodeURIComponent(b.name)}`, { method: 'PATCH', body, ifMatch: b.version });
      return api('v1/blueprints', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved blueprint ${saved.name}.` : `Created blueprint ${saved.name}.`);
  await refresh();
}

async function deleteBlueprint(b: any) {
  const done = await ask({
    title: `Delete blueprint ${b.name}?`,
    text: 'Blueprints that agents still use cannot be deleted; move those agents to another blueprint first.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete blueprint', busy: 'Deleting…',
    submit: () => api(`v1/blueprints/${encodeURIComponent(b.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted blueprint ${b.name}.`);
  await refresh();
}

// Custom modules must declare `package agentgov.custom.<name>` (hyphens become underscores).
const policyPackage = (name: string) => `agentgov.custom.${(name || '<name>').replace(/-/g, '_')}`;
const POLICY_TEMPLATE = (name: string) => `# Rules here can add to deny, require_approval and redact. They see the same
# input as the built-in library; data.agentgov.context has helpers for the
# calling agent and tool server (see docs/policies.md).
package ${policyPackage(name)}

deny contains msg if {
\tinput.phase == "request"
\tinput.resource.name == "delete_everything"
\tmsg := "delete_everything is disabled by organisation policy"
}
`;
// Where the policy form keeps the template it last put in the source: with the form's
// values, under a key no field has.
const TEMPLATE_KEY = 'rego_template';

/** Add an organisation policy (no `p`) or replace one's source and settings. */
export async function policyFormFlow(p: any): Promise<void> {
  const editing = Boolean(p);
  const saved = await ask<any>({
    title: editing ? `Edit policy ${p.name}` : 'Add an organisation policy',
    text: 'The control plane compiles the module with the built-in library and evaluates it on sample calls before saving. Saved policies reach OPA with the next policy bundle.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save policy' : 'Add policy', busy: 'Checking…', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'prod-verified-only', hint: `${NAME_HINT} The module's package is agentgov.custom.<name>, with hyphens as underscores.` },
      { id: 'description', label: 'Description', value: p?.description || '' },
      { id: 'rego', label: 'Rego source', type: 'code', rows: 14, required: true, file: '.rego', value: p ? p.rego : POLICY_TEMPLATE('') },
      { id: 'enabled', label: 'Enabled', type: 'checkbox', value: p ? p.enabled : true, hint: 'Disabled policies are kept but not sent to OPA.' },
    ],
    // Keep the template's package line in step with the name until the source is edited.
    onChange: editing ? undefined : (values: Values, changed: string) => {
      if (changed !== 'name') return undefined;
      const last = values[TEMPLATE_KEY] ?? POLICY_TEMPLATE('');
      if (values.rego !== last) return undefined;
      const rego = POLICY_TEMPLATE(String(values.name).trim());
      return { rego, [TEMPLATE_KEY]: rego };
    },
    submit: (v) => {
      const body = { description: v.description, rego: v.rego, enabled: v.enabled };
      if (editing) return api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'PUT', body, ifMatch: p.version });
      return api('v1/policies', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved policy ${saved.name} (version ${saved.version}).` : `Added policy ${saved.name}.`);
  await refresh();
}

export async function togglePolicy(p: any): Promise<void> {
  const enable = !p.enabled;
  const done = await ask({
    title: `${enable ? 'Enable' : 'Disable'} policy ${p.name}?`,
    text: enable
      ? 'The module is checked again, then OPA enforces it with the next policy bundle.'
      : 'OPA stops enforcing the module with the next policy bundle. Its source is kept.',
    tone: enable ? 'primary' : 'danger', iconName: enable ? 'check' : 'minus', confirm: enable ? 'Enable policy' : 'Disable policy',
    busy: enable ? 'Checking…' : 'Saving…',
    submit: () => api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'PUT', body: { enabled: enable } }),
  });
  if (!done) return;
  toast(`${enable ? 'Enabled' : 'Disabled'} policy ${p.name}.`);
  await refresh();
}

export async function deletePolicy(p: any): Promise<void> {
  const done = await ask({
    title: `Delete policy ${p.name}?`,
    text: 'OPA stops enforcing it with the next policy bundle, and its source is removed. Export the manifests first if you may want it back.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete policy', busy: 'Deleting…',
    submit: () => api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted policy ${p.name}.`);
  await refresh();
}

/** Apply YAML manifests: what `agentgov apply -f` sends, from the browser. */
async function importManifests() {
  const result = await ask<any>({
    title: 'Import manifests',
    text: 'Apply Blueprint, ToolServer, Policy and Agent manifests, as exported from this page or written for `agentgov apply`. Applying is idempotent: unchanged resources are left alone. Policies need their Rego inline under spec.rego.',
    iconName: 'upload', confirm: 'Apply manifests', busy: 'Applying…', wide: true,
    fields: [{ id: 'yaml', label: 'Manifests (YAML)', type: 'code', rows: 14, required: true, file: '.yaml,.yml', placeholder: 'apiVersion: agentgov/v1alpha1\nkind: Blueprint\nmetadata:\n  name: customer-support\nspec:\n  …' }],
    submit: (v) => api('v1/apply', { method: 'POST', text: v.yaml, contentType: 'application/yaml' }),
  });
  if (!result?.results) return;
  const changed = result.results.filter((r: any) => r.action !== 'unchanged');
  await ask({
    title: changed.length ? `Applied ${plural(changed.length, 'change')}` : 'Nothing to change',
    iconName: 'check-circle', confirm: 'Done', cancel: null,
    extra: (
      <ul className="apply-results" role="list">
        {result.results.map((r: any, i: number) => (
          <li key={i}>
            <code>{`${r.kind.toLowerCase()}/${r.name}`}</code>
            <PlainChip text={humanize(r.action)} tone={r.action === 'unchanged' ? null : 'good'} />
          </li>
        ))}
      </ul>
    ),
  });
  void refreshBadges();
  await refresh();
}

function PermissionList({ grants }: { grants: any[] | null | undefined }) {
  if (!grants?.length) return <p className="muted small">No tools granted.</p>;
  return (
    <ul className="perm-list" role="list">
      {grants.map((g, i) => (
        <li key={i}>
          <span className="perm-server">{g.server}</span>
          <div className="chip-row">{g.tools.map((t: string, j: number) => <PlainChip key={j} text={t} mono />)}</div>
        </li>
      ))}
    </ul>
  );
}

// Who a blueprint's agents act for (acting-for-people), and who decides approvals made for a person.
const ACTS_FOR: Record<string, string> = {
  either: 'People, or itself',
  people: 'Only people: every call is for a person',
  itself: 'Only itself: never for a person',
};
const APPROVALS_BY: Record<string, string> = { approvers: 'Approvers', person: 'The person the agent acted for' };

/** Who a blueprint's (or an agent's) agents act for, in words. */
export function actsFor(x: any): ReactNode {
  const groups: string[] = x.people_groups || [];
  const who = ({ either: 'People or itself', people: 'People only', itself: 'Itself only' } as Record<string, string>)[x.acts_for] || humanize(x.acts_for || 'either');
  return x.acts_for !== 'itself' && groups.length ? (
    <span>
      {`${who}; people in `}
      <span className="chip-row" style={{ display: 'inline-flex' }}>{groups.map((g, i) => <PlainChip key={i} text={g} mono />)}</span>
    </span>
  ) : who;
}

function BlueprintCard({ b, used, servers }: { b: any; used: number; servers: any[] }) {
  const labels = Object.entries(b.labels || {});
  const tier = b.risk_tier === 'minimal' ? 'low' : b.risk_tier;
  return (
    <Card
      title={b.name} level="h3" id={`bp-${b.id}`}
      sub={b.description}
      actions={[<PlainChip key="tier" text={`${humanize(b.risk_tier)} risk tier`} tone={toneOf('risk', tier)} iconName={statusMeta('risk', tier)[1]} />]}
      foot={can('admin') ? (
        <div className="btn-row">
          <button type="button" className="btn btn--sm" onClick={guarded(() => blueprintFormFlow(b, servers))}><Icon name="edit" />Edit</button>
          <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => deleteBlueprint(b)}><Icon name="trash" />Delete</button>
        </div>
      ) : null}
    >
      <Facts rows={[
        ['Used by', used ? <a href="#/agents">{plural(used, 'agent')}</a> : <span className="muted">No agents</span>],
        ['Sponsor', b.require_sponsor ? 'Required before activation' : 'Not required'],
        b.require_workload_identity ? ['Authentication', 'A workload identity, never a client secret'] : null,
        ['Attestation', b.attestation_days ? `Every ${plural(b.attestation_days, 'day')}` : 'Not required'],
        ['Acts for', actsFor(b)],
        b.approvals_by === 'person' ? ['Approvals', APPROVALS_BY.person] : null,
        (b.agent_access || []).length ? ['May call agents', <div className="chip-row">{b.agent_access.map((x: string, i: number) => <PlainChip key={i} text={x} mono />)}</div>] : null,
        labels.length ? ['Labels', <div className="chip-row">{labels.map(([k, v]) => <PlainChip key={k} text={`${k}=${v}`} mono />)}</div>] : null,
      ]} />
      <div className="field-label">Permissions</div>
      <PermissionList grants={b.permissions} />
    </Card>
  );
}

function PackageCard({ pk, servers, blueprints }: { pk: any; servers: any[]; blueprints: any[] }) {
  const held = pk.assignments.active + pk.assignments.expired;
  return (
    <Card
      title={pk.name} level="h3" id={`pkg-${pk.id}`}
      sub={pk.description}
      actions={[<PlainChip key="duration" text={`Up to ${plural(pk.duration_days, 'day')}`} iconName="clock" />]}
      foot={can('admin') ? (
        <div className="btn-row">
          <button type="button" className="btn btn--sm" onClick={guarded(() => packageForm(pk, servers, blueprints))}><Icon name="edit" />Edit</button>
          <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => deletePackage(pk))}><Icon name="trash" />Delete</button>
        </div>
      ) : null}
    >
      {/* Each value in a span of its own, as today. */}
      <Facts rows={[
        ['Held by', <span>{held ? plural(held, 'agent') : <span className="muted">No agents</span>}{pk.assignments.requested ? ` · ${fmt(pk.assignments.requested)} waiting` : ''}</span>],
        ['Requests', <span>{pk.approval ? 'An approver decides' : 'Granted at once'}</span>],
        ['Reviews', <span>{pk.review_days ? `Every ${plural(pk.review_days, 'day')}` : 'None'}</span>],
        ['For agents on', <span>{pk.blueprints.length ? pk.blueprints.join(', ') : 'Any blueprint'}</span>],
        pk.model_access.length ? ['Models', <span><div className="chip-row">{pk.model_access.map((m: any, i: number) => <PlainChip key={i} text={`${m.provider}: ${m.models.join(', ')}`} mono />)}</div></span>] : null,
        pk.agent_access.length ? ['May call agents', <span><div className="chip-row">{pk.agent_access.map((x: string, i: number) => <PlainChip key={i} text={x} mono />)}</div></span>] : null,
      ]} />
      {pk.permissions.length ? <><div className="field-label">Tools</div><PermissionList grants={pk.permissions} /></> : null}
    </Card>
  );
}

async function packageForm(pk: any, servers: any[], blueprints: any[]) {
  const editing = Boolean(pk);
  const saved = await ask<any>({
    title: editing ? `Edit access package ${pk.name}` : 'New access package',
    text: editing
      ? 'Every agent that holds it gets the change as soon as OPA loads the updated policy bundle.'
      : 'Agents hold what it grants for a while once a request is approved. Before it expires, the people responsible for the agent are told, so they can renew it.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save changes' : 'Create package', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'crm-write', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', value: pk?.description || '' },
      {
        id: 'permissions', label: 'Tool grants', type: 'code', rows: 3, value: formatGrants(pk?.permissions), placeholder: 'crm: update_customer',
        hint: `One server per line; tool names can use * wildcards.${servers.length ? ` Registered servers: ${servers.map((ts) => ts.name).join(', ')}.` : ''}`,
      },
      { id: 'model_access', label: 'Model access', type: 'code', rows: 2, value: formatModelAccess(pk?.model_access), placeholder: 'openai: gpt-4.1', hint: 'One provider per line.' },
      { id: 'agent_access', label: 'Agents it lets call', value: (pk?.agent_access || []).join(', '), placeholder: 'billing-agent', mono: true, hint: 'Over A2A, separated by commas; names can use * wildcards.' },
      {
        type: 'row',
        fields: [
          { id: 'duration_days', label: 'Lasts at most (days)', type: 'number', min: 1, value: pk?.duration_days ?? 90, required: true },
          { id: 'review_days', label: 'Review every (days)', type: 'number', min: 1, value: pk?.review_days ?? '', hint: 'Empty: no reviews.' },
        ],
      },
      { id: 'approval', label: 'An approver decides each request', type: 'checkbox', value: pk ? pk.approval : true, hint: 'Otherwise it is granted as soon as someone allowed asks for it.' },
      {
        id: 'blueprints', label: 'For agents on these blueprints', value: (pk?.blueprints || []).join(', '), mono: true,
        hint: `Separated by commas. Empty: any agent.${blueprints.length ? ` Blueprints: ${blueprints.map((b) => b.name).join(', ')}.` : ''}`,
      },
    ],
    submit: (v) => {
      const whole = (text: string, label: string) => {
        if (!text) return null;
        const n = Number(text);
        if (!(Number.isInteger(n) && n > 0 && n <= 365)) throw new Error(`${label} is a whole number of days from 1 to 365.`);
        return n;
      };
      const body = {
        description: v.description, permissions: parseGrants(v.permissions), model_access: parseModelAccess(v.model_access),
        agent_access: parseList(v.agent_access), blueprints: parseList(v.blueprints), approval: v.approval,
        duration_days: whole(v.duration_days, 'How long it lasts'), review_days: whole(v.review_days, 'The review period'),
      };
      if (editing) return api(`v1/access-packages/${encodeURIComponent(pk.name)}`, { method: 'PATCH', body, ifMatch: pk.version });
      return api('v1/access-packages', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved access package ${saved.name}.` : `Created access package ${saved.name}.`);
  await refresh();
}

async function deletePackage(pk: any) {
  const done = await ask({
    title: `Delete access package ${pk.name}?`,
    text: 'Packages that agents hold or ask for cannot be deleted: revoke or deny those first.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete package', busy: 'Deleting…',
    submit: () => api(`v1/access-packages/${encodeURIComponent(pk.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted access package ${pk.name}.`);
  await refresh();
}
