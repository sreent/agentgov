// Management rules: what to do about agents that meet some conditions for long enough,
// after telling their people; what each matches now, and running them.

import { useState, type ReactNode } from 'react';
import { ask, type Values } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { AgentLink, Callout, Card, Chip, Facts, TimeEl } from '../components/ui';
import { api } from '../lib/api';
import { fmt, humanize, plural } from '../lib/format';
import { formatLabels, parseLabels, parseList } from '../lib/forms';
import { refresh } from '../lib/router';
import { can } from '../lib/session';
import { NAME_HINT } from '../lib/shared';

const RULE_ACTIONS: Record<string, string> = {
  issue: 'Raise an issue',
  assign_owner: 'Give it an owner',
  block: 'Block it',
  delete: 'Delete it',
  revoke_access: 'Revoke its access packages',
};
const RULE_MISSING: Record<string, string> = { workload_identity: 'workload identity' };

// What an agent must meet, in words.
function ruleWhen(c: any): string {
  const parts = [];
  if (c.inactive_days) parts.push(`no activity for ${plural(c.inactive_days, 'day')}`);
  if (c.missing) parts.push(`no ${c.missing.map((m: string) => RULE_MISSING[m] || m).join(' or no ')}`);
  if (c.attestation_overdue_days != null) parts.push(c.attestation_overdue_days ? `attestation overdue for ${plural(c.attestation_overdue_days, 'day')}` : 'attestation overdue');
  if (c.findings) parts.push(`an open ${c.finding_severity ? `${c.finding_severity}+ ` : ''}finding: ${c.findings.join(', ')}`);
  if (c.risk_level) parts.push(`${c.risk_level} risk or more`);
  if (c.status) parts.push(`it is ${c.status.join(' or ')}`);
  return parts.join(' · ') || '—';
}

const RULE_PLATFORMS: Record<string, string> = {
  gateway: 'the gateway', 'microsoft-365': 'Microsoft 365', 'copilot-studio': 'Copilot Studio',
  aws: 'AWS', 'google-cloud': 'Google Cloud', salesforce: 'Salesforce', databricks: 'Databricks',
  'microsoft-foundry': 'Microsoft Foundry',
};

/** The agents a rule's scope names, in words. */
export function ruleScope(scope: any): string {
  const parts = [];
  if (scope.platforms?.length) parts.push(`on ${scope.platforms.map((x: string) => RULE_PLATFORMS[x] || x).join(' or ')}`);
  for (const [key, label] of [['blueprints', 'blueprint'], ['teams', 'team'], ['environments', 'environment']]) {
    if (scope[key]?.length) parts.push(`${label} ${scope[key].join(' or ')}`);
  }
  if (scope.labels && Object.keys(scope.labels).length) parts.push(`labelled ${formatLabels(scope.labels)}`);
  return parts.length ? parts.join(' · ') : 'All agents';
}

function ruleThen(r: any): string {
  const what = r.action === 'assign_owner' ? `Make ${r.params.owner} its owner` : RULE_ACTIONS[r.action] || r.action;
  if (r.action === 'issue') return r.after_days ? `${what}, once it has matched for ${plural(r.after_days, 'day')}` : `${what}, at once`;
  return `${what}, ${plural(r.after_days, 'day')} after telling its people`;
}

/** Why the rules don't act, if they don't: the features they need, off or monitored. */
export function RulesNote({ modes }: { modes: Record<string, string> }) {
  const mode = modes['management-rules'];
  if (mode === 'off') return <Callout tone="warning" icon="minus"><span><strong>Off: </strong>management rules are off in Features, so no rule runs.</span></Callout>;
  if (modes['posture-checks'] === 'off') return <Callout tone="warning" icon="triangle"><span><strong>Not running: </strong>rules run after each posture scan, and posture checks are off in Features.</span></Callout>;
  if (mode === 'monitor') return <Callout tone="neutral" icon="eye"><span><strong>Monitored: </strong>rules tell nobody and change nothing; they record what they would have done. Enforce the feature in Features, and a rule, for it to act.</span></Callout>;
  return null;
}

export function RuleCard({ r, blueprints }: { r: any; blueprints: any[] }) {
  const capped = r.mode !== r.effective_mode;
  return (
    <Card
      title={r.name} level="h3" id={`rule-${r.id}`}
      sub={r.description}
      actions={[<Chip key="mode" kind="mode" value={r.effective_mode} title={capped ? `${humanize(r.mode)} in the rule, ${r.effective_mode} by the feature` : null} />]}
      foot={(
        <div className="btn-row">
          <button type="button" className="btn btn--sm" onClick={guarded(() => rulePreview(r))}><Icon name="eye" />Preview</button>
          {can('admin') ? (
            <>
              <button type="button" className="btn btn--sm" onClick={guarded(() => ruleForm(r, blueprints))}><Icon name="edit" />Edit</button>
              <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => deleteRule(r))}><Icon name="trash" />Delete</button>
            </>
          ) : null}
        </div>
      )}
    >
      <Facts rows={[
        ['When', ruleWhen(r.conditions)],
        ['Agents', ruleScope(r.scope)],
        ['Then', ruleThen(r)],
        ['At once', `${plural(r.max_actions, 'agent')} at most`],
        ['Matching', (
          <>
            {r.matches.matching ? plural(r.matches.matching, 'agent') : <span className="muted">No agents</span>}
            {r.matches.acted ? ` · acted on ${fmt(r.matches.acted)}` : ''}
            {r.matches.would_have_acted ? ` · would have acted on ${fmt(r.matches.would_have_acted)}` : ''}
          </>
        )],
        capped ? ['Mode', `${humanize(r.mode)} in the rule; ${r.effective_mode} by the feature`] : null,
      ]} />
    </Card>
  );
}

// What a rule matches now and would do: for a saved rule, or the form's draft.
function RulePreviewView({ view }: { view: any }) {
  const notes: ReactNode[] = [];
  if (!view.running) notes.push(<Callout key="running" tone="warning" icon="triangle"><span><strong>Not running: </strong>{`${view.why_not}.`}</span></Callout>);
  else if (view.mode === 'monitor') notes.push(<Callout key="monitor" tone="neutral" icon="eye"><span><strong>Monitored: </strong>it tells nobody and changes nothing; it records what it would have done.</span></Callout>);
  if (view.held_back) notes.push(<Callout key="held" tone="critical" icon="octagon"><span><strong>Too many at once: </strong>{`${fmt(view.due)} agents are due, more than its limit of ${fmt(view.max_actions)}, so it acts on none of them and raises an issue about itself.`}</span></Callout>);
  return (
    <div className="stack rule-preview">
      <p className="muted">{`${plural(view.matching, 'agent')} ${view.matching === 1 ? 'matches' : 'match'} now${view.due ? `, ${fmt(view.due)} due` : ''}.`}</p>
      {notes}
      {view.agents.length ? (
        <ul className="access-list" role="list">
          {view.agents.map((e: any, i: number) => (
            <li key={i} className="access-row">
              <div className="access-main">
                <div className="cell-title"><AgentLink id={e.agent_id} name={e.agent} />{' '}<Chip kind="rule" value={e.state} /></div>
                <div className="cell-sub break">{humanize(e.detail)}{e.reasons.length ? ` · ${e.reasons.join('; ')}` : ''}</div>
              </div>
            </li>
          ))}
        </ul>
      ) : null}
      {view.unknown_count ? (
        <details className="disclosure">
          <summary><Icon name="chevron" />{`Can't tell for ${plural(view.unknown_count, 'agent')}`}</summary>
          <ul className="access-list" role="list">
            {view.unknown.map((u: any, i: number) => (
              <li key={i} className="access-row">
                <div className="access-main">
                  <div className="cell-title"><AgentLink id={u.agent_id} name={u.agent} /></div>
                  <div className="cell-sub break">{u.why}</div>
                </div>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

async function rulePreview(r: any) {
  const view = await api(`v1/rules/${encodeURIComponent(r.name)}/preview`);
  await ask({ title: `Preview: ${r.name}`, text: 'The agents the rule matches now, since when, and what it will do to each.', iconName: 'eye', confirm: 'Close', cancel: null, wide: true, extra: <RulePreviewView view={view} /> });
}

function ruleBody(v: Values) {
  const whole = (text: string, label: string, min: number, max: number) => {
    if (text === '' || text == null) return null;
    const n = Number(text);
    if (!(Number.isInteger(n) && n >= min && n <= max)) throw new Error(`${label} is a whole number from ${min} to ${max}.`);
    return n;
  };
  const pick = (entries: [string, unknown][]) => Object.fromEntries(entries.filter(([, value]) => value != null && value !== '' && !(Array.isArray(value) && !value.length)));
  const labels = parseLabels(v.scope_labels);
  return {
    description: v.description,
    conditions: pick([
      ['inactive_days', whole(v.inactive_days, 'No activity for', 1, 3650)],
      ['attestation_overdue_days', whole(v.attestation_overdue_days, 'Attestation overdue for', 0, 3650)],
      ['missing', parseList(v.missing)],
      ['findings', parseList(v.findings)],
      ['finding_severity', v.finding_severity],
      ['risk_level', v.risk_level],
      ['status', parseList(v.status)],
    ]),
    scope: pick([
      ['blueprints', parseList(v.blueprints)], ['teams', parseList(v.teams)],
      ['environments', parseList(v.environments)], ['platforms', parseList(v.platforms)],
      ['labels', Object.keys(labels).length ? labels : null],
    ]),
    action: v.action,
    params: v.action === 'assign_owner' ? { owner: v.owner } : {},
    after_days: whole(v.after_days, 'After', 0, 365) ?? 14,
    max_actions: whole(v.max_actions, 'At most at once', 1, 1000) ?? 10,
    severity: v.severity,
    mode: v.mode,
    labels: parseLabels(v.labels),
  };
}

// Below the rule form: what the form's draft matches, asked for with its button.
function RuleFormPreview({ values, r }: { values: Values; r: any }) {
  const [box, setBox] = useState<ReactNode>(null);
  const [busy, setBusy] = useState(false);
  const preview = async () => {
    const v = Object.fromEntries(Object.entries(values).map(([k, x]) => [k, typeof x === 'string' ? x.trim() : x]));
    setBusy(true);
    try {
      const view = await api('v1/rules/preview', { method: 'POST', body: { ...ruleBody(v), name: v.name || r?.name || 'draft' } });
      setBox(<RulePreviewView view={view} />);
    } catch (err: any) {
      setBox(<Callout tone="critical" icon="octagon">{err.message}</Callout>);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack">
      <div className="btn-row">
        <button type="button" className="btn btn--sm" disabled={busy} onClick={preview}><Icon name="eye" />Preview the agents it matches</button>
      </div>
      <div className="rule-preview-box" aria-live="polite">{box}</div>
    </div>
  );
}

/** Create a rule (no `r`) or edit one, with a preview of what it matches before saving. */
export async function ruleForm(r: any, blueprints: any[]): Promise<void> {
  const editing = Boolean(r);
  const teams: any[] = await api('v1/teams').catch(() => []);
  const c = r?.conditions || {};
  const scope = r?.scope || {};
  const options = (values: string[], any?: string) => [...(any ? [{ value: '', label: any }] : []), ...values.map((x) => ({ value: x, label: humanize(x) }))];
  const saved = await ask<any>({
    title: editing ? `Edit rule ${r.name}` : 'New management rule',
    text: 'When an agent meets all its conditions, the rule tells the agent’s people at once, and acts after its days of notice if the agent still matches. Monitored, it only records what it would have done.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save changes' : 'Create rule', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'inactive-agents', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', rows: 2, value: r?.description || '' },
      { type: 'section', label: 'When an agent has all of these' },
      {
        type: 'row',
        fields: [
          { id: 'inactive_days', label: 'No activity for (days)', type: 'number', min: 1, value: c.inactive_days ?? '' },
          { id: 'attestation_overdue_days', label: 'Attestation overdue for (days)', type: 'number', min: 0, value: c.attestation_overdue_days ?? '' },
        ],
      },
      { id: 'missing', label: 'No', value: (c.missing || []).join(', '), mono: true, hint: 'Any of owner, sponsors, team, blueprint, workload_identity, separated by commas.' },
      {
        type: 'row',
        fields: [
          { id: 'findings', label: 'An open issue of type', value: (c.findings || []).join(', '), mono: true, placeholder: 'agent.stale', hint: '* wildcards, separated by commas.' },
          { id: 'finding_severity', label: 'Of severity', type: 'select', value: c.finding_severity || '', options: options(['low', 'medium', 'high', 'critical'], 'Any') },
        ],
      },
      {
        type: 'row',
        fields: [
          { id: 'risk_level', label: 'Risk at least', type: 'select', value: c.risk_level || '', options: options(['low', 'medium', 'high', 'critical'], 'Any') },
          { id: 'status', label: 'Status', value: (c.status || []).join(', '), mono: true, hint: 'pending, active, blocked or discovered (unmanaged).' },
        ],
      },
      { type: 'section', label: 'Which agents it looks at' },
      {
        type: 'row',
        fields: [
          { id: 'blueprints', label: 'Blueprints', value: (scope.blueprints || []).join(', '), mono: true, hint: `Empty: all of them.${blueprints.length ? ` Blueprints: ${blueprints.map((b) => b.name).join(', ')}.` : ''}` },
          { id: 'teams', label: 'Teams', value: (scope.teams || []).join(', '), mono: true, hint: teams.length ? `Teams: ${teams.map((t) => t.name).join(', ')}.` : null },
        ],
      },
      {
        type: 'row',
        fields: [
          { id: 'platforms', label: 'Platforms', value: (scope.platforms || []).join(', '), mono: true, hint: 'gateway, microsoft-365, copilot-studio, aws, google-cloud, salesforce, databricks or microsoft-foundry.' },
          { id: 'environments', label: 'Environments', value: (scope.environments || []).join(', '), mono: true },
        ],
      },
      { id: 'scope_labels', label: 'With labels', value: formatLabels(scope.labels), mono: true, hint: 'key=value, separated by commas. Agents labelled agentgov/exempt-rules with the rule’s name, or *, are left out.' },
      { type: 'section', label: 'What it does' },
      {
        type: 'row',
        fields: [
          { id: 'action', label: 'Action', type: 'select', required: true, value: r?.action || 'issue', options: Object.entries(RULE_ACTIONS).map(([value, label]) => ({ value, label })) },
          { id: 'owner', label: 'Owner it gives', value: r?.params?.owner || '', mono: true, datalist: teams.map((t) => t.name), hint: 'For "Give it an owner": a team, or an email address.' },
        ],
      },
      {
        type: 'row',
        fields: [
          { id: 'after_days', label: 'After (days)', type: 'number', min: 0, required: true, value: r?.after_days ?? 14, hint: 'How long an agent matches before the action. Rules that change something give a day’s notice at least.' },
          { id: 'max_actions', label: 'At most at once', type: 'number', min: 1, required: true, value: r?.max_actions ?? 10, hint: 'More agents due at once: it acts on none.' },
        ],
      },
      {
        type: 'row',
        fields: [
          { id: 'severity', label: 'Its issues’ severity', type: 'select', required: true, value: r?.severity || 'medium', options: options(['low', 'medium', 'high', 'critical']) },
          { id: 'mode', label: 'Mode', type: 'select', required: true, value: r?.mode || 'monitor', options: [{ value: 'monitor', label: 'Monitor: record what it would do' }, { value: 'enforce', label: 'Enforce: tell, then act' }, { value: 'off', label: 'Off' }] },
        ],
      },
      { id: 'labels', label: 'Labels', value: formatLabels(r?.labels), mono: true },
    ],
    after: ({ values }) => <RuleFormPreview values={values} r={r} />,
    submit: (v) => {
      const body = ruleBody(v);
      if (editing) return api(`v1/rules/${encodeURIComponent(r.name)}`, { method: 'PATCH', body, ifMatch: r.version });
      return api('v1/rules', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved rule ${saved.name}.` : `Created rule ${saved.name} (${saved.effective_mode}).`);
  await refresh();
}

async function deleteRule(r: any) {
  const done = await ask({
    title: `Delete rule ${r.name}?`,
    text: 'Its open issues are resolved. What it did stays done: blocked agents stay blocked until someone unblocks them.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete rule', busy: 'Deleting…',
    submit: () => api(`v1/rules/${encodeURIComponent(r.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted rule ${r.name}.`);
  await refresh();
}

/** Run every rule now, and say what they did. */
export async function runRules(): Promise<void> {
  const out = await api('v1/rules/evaluate', { method: 'POST' });
  if (out.off) {
    toast('Management rules are off in Features.', { tone: 'warning' });
  } else {
    const sum = (key: string) => Object.values(out as Record<string, Record<string, number>>).reduce((n, counts) => n + (counts[key] || 0), 0);
    toast(`Rules ran: ${plural(sum('matching'), 'agent')} matching, ${fmt(sum('acted'))} acted on, ${fmt(sum('would_act'))} would have been, ${fmt(sum('held_back'))} held back.`);
  }
  await refresh();
}

/** The rules an agent matches (agentRulesCard(rows)). */
export function AgentRulesCard({ rows }: { rows: any }) {
  if (!Array.isArray(rows) || !rows.length) return null;
  return (
    <Card title="Management rules" sub="The rules it matches, and what each will do or did.">
      <ul className="access-list" role="list">
        {rows.map((r: any, i: number) => (
          <li key={i} className="access-row">
            <div className="access-main">
              <div className="cell-title">{r.rule}{' '}<Chip kind="rule" value={r.state} /></div>
              <div className="cell-sub break">{humanize(r.detail)}{' · matching since '}<TimeEl iso={r.since} /></div>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
