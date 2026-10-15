// What an agent is told to do (its system prompt), from each source that reports it,
// checked for harmful or malicious content; and the agent's open issues.

import type { ReactNode } from 'react';
import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, Chip, EmptyState, PlainChip, TimeEl } from '../components/ui';
import { api } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { humanize, plural } from '../lib/format';
import { refresh } from '../lib/router';
import { can } from '../lib/session';
import { SEVERITY_ORDER } from '../lib/status';

const INSTRUCTION_SOURCES: Record<string, string> = {
  registered: 'Registered', telemetry: 'Reported in telemetry', 'microsoft-365': 'From Microsoft 365',
  aws: 'From AWS', 'google-cloud': 'From Google Cloud', salesforce: 'From Salesforce', databricks: 'From Databricks',
  'microsoft-foundry': 'From Microsoft Foundry',
};

function classifierLine(c: any, settings: any): ReactNode {
  if (c.state === 'unchecked') {
    return (
      <Callout tone="neutral" icon="minus">
        <span>
          {'Not checked: instruction checks were off when these arrived. They are checked once instruction checks are on ('}
          <a href="#/features">Features</a>{')).'}
        </span>
      </Callout>
    );
  }
  if (!settings?.enabled) return <p className="hint">{"Checked by AgentGov's rules. No classifier is configured."}</p>;
  const model = c.model || settings.model;
  if (c.state === 'pending') return <p className="hint"><Icon name="clock" />{` The classifier (${model}) is still checking these instructions.`}</p>;
  if (c.state === 'error') return <Callout tone="warning" icon="triangle">{`The classifier (${model}) failed: ${c.error}`}</Callout>;
  if (c.state === 'done') {
    const flagged = Object.entries(c.verdicts || {}).filter(([, v]) => v === 'yes').map(([k]) => humanize(k));
    return <p className="hint">{`Checked by AgentGov's rules and the classifier (${model})${flagged.length ? `, which flagged ${flagged.join(', ')}` : ', which flagged nothing'}.`}</p>;
  }
  return <p className="hint">{"Checked by AgentGov's rules; the classifier hasn't checked them yet."}</p>;
}

function issueList(issues: any[]): ReactNode {
  if (!issues.length) return <p className="tone-text-good small"><Icon name="check-circle" />{' No problems found.'}</p>;
  return (
    <ul className="issue-list" role="list">
      {issues.map((i, n) => (
        <li key={n}>
          <div className="issue-head">
            <Chip kind="severity" value={i.severity} />
            <strong>{i.title}</strong>
            {i.detector === 'classifier' ? <PlainChip text="Classifier" title="Judged by the classifier" /> : null}
          </div>
          {i.excerpt ? <q className="issue-excerpt">{i.excerpt}</q> : null}
        </li>
      ))}
    </ul>
  );
}

/** An agent's instructions, from each source that reports them, and what checking them found. */
export function InstructionsCard({ a, view }: { a: any; view: any }) {
  if (view instanceof Error) {
    return (
      <Card title="Instructions">
        <Callout tone="critical" icon="alert-circle">{`The instructions couldn't be loaded. ${view.message}`}</Callout>
      </Card>
    );
  }
  const sources: any[] = view.sources || [];
  const admin = can('admin', a) && a.status !== 'deleted';
  const actions = admin ? [
    sources.length ? (
      <button key="rescan" type="button" className="btn btn--sm" onClick={guarded(() => rescanInstructions(a))}>
        <Icon name="refresh" />Rescan
      </button>
    ) : null,
    sources.some((x) => x.source === 'registered') ? null : (
      <button key="add" type="button" className="btn btn--sm" onClick={guarded(() => editInstructions(a, null))}>
        <Icon name="plus" />Add instructions
      </button>
    ),
  ].filter(Boolean) : null;
  const body = sources.length ? sources.map((x) => (
    <div key={x.source} className="instructions-source">
      <div className="instructions-head">
        <div>
          <strong>{INSTRUCTION_SOURCES[x.source] || x.source_name}</strong>
          <div className="cell-sub">{`From ${x.reported_by}, changed `}<TimeEl iso={x.updated_at} /></div>
        </div>
        {admin ? (
          <div className="btn-row">
            {x.source === 'registered' ? (
              <button type="button" className="btn btn--sm" onClick={guarded(() => editInstructions(a, x))}><Icon name="edit" />Edit</button>
            ) : null}
            <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => forgetInstructions(a, x))}>
              <Icon name="trash" />Forget
            </button>
          </div>
        ) : null}
      </div>
      {x.classifier?.state === 'unchecked' ? null : issueList(x.issues || [])}
      {classifierLine(x.classifier || {}, view.classifier)}
      <details className="disclosure">
        <summary><Icon name="chevron" />Show the instructions</summary>
        <pre className="kv-pre instructions-text" tabIndex={0}>{x.text}</pre>
        {x.truncated ? <p className="hint">Only the beginning is kept.</p> : null}
      </details>
    </div>
  )) : (
    <EmptyState
      title="No instructions known"
      text="Agents that capture message content report them in telemetry (gen_ai.system_instructions), Microsoft 365 reports declarative agents' instructions, and they can be added here or in a manifest."
    />
  );
  return (
    <Card
      title="Instructions"
      sub="What the agent is told to do (its system prompt), checked for harmful or malicious content. Credentials in it are redacted."
      actions={actions}
    >
      {body}
    </Card>
  );
}

async function editInstructions(a: any, current: any) {
  const saved = await ask<any>({
    title: current ? `Edit ${a.name}'s instructions` : `Add instructions for ${a.name}`,
    text: 'The instructions are checked as soon as they are saved, and the result is recorded in the evidence ledger. Credentials in them are redacted before they are stored.',
    iconName: 'edit', confirm: 'Save and check', busy: 'Checking…', wide: true,
    fields: [{ id: 'text', label: 'Instructions', type: 'code', rows: 14, required: true, file: '.txt,.md', value: current?.text || '', placeholder: 'You are the Contoso IT helpdesk assistant. …' }],
    submit: (v) => api(`v1/agents/${encodeURIComponent(a.id)}/instructions`, { method: 'PUT', body: { text: v.text } }),
  });
  if (!saved) return;
  const n = (saved.issues || []).length;
  toast(n ? `Saved. ${plural(n, 'problem')} found in the instructions.` : 'Saved. No problems found.', { tone: n ? 'warning' : 'good' });
  void refreshBadges();
  await refresh();
}

async function forgetInstructions(a: any, x: any) {
  const done = await ask({
    title: `Forget ${(INSTRUCTION_SOURCES[x.source] || x.source).toLowerCase()} instructions?`,
    text: x.source === 'registered'
      ? 'The registered instructions are removed. An issue about them is resolved.'
      : 'AgentGov forgets this copy. If the source reports the instructions again, they come back and are checked again.',
    tone: 'danger', iconName: 'trash', confirm: 'Forget', busy: 'Forgetting…',
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}/instructions?source=${encodeURIComponent(x.source)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Forgot ${a.name}'s ${x.source} instructions.`);
  void refreshBadges();
  await refresh();
}

async function rescanInstructions(a: any) {
  const out = await api(`v1/agents/${encodeURIComponent(a.id)}/instructions/rescan`, { method: 'POST' });
  toast(`Checked ${plural(out.rescanned, 'set')} of instructions again.`);
  void refreshBadges();
  await refresh();
}

/** The agent's open issues, the most severe first; nothing when there are none. */
export function AgentFindingsCard({ list }: { list: any }) {
  if (list instanceof Error || !list.length) return null;
  const sorted = list.slice().sort((x: any, y: any) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity));
  return (
    <Card
      title="Open issues"
      sub={plural(sorted.length, 'issue')}
      actions={[<a key="all" className="btn btn--sm btn--ghost" href="#/findings">All issues<Icon name="arrow" /></a>]}
      flush
    >
      <ul className="feed" role="list">
        {sorted.map((f: any) => (
          <li key={f.id}>
            <div className="feed-top"><Chip kind="severity" value={f.severity} /><span className="feed-meta"><TimeEl iso={f.last_seen} /></span></div>
            <span>{f.title}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
