// Approvals: everything waiting for a decision someone can make (calls policy held, access
// asked for agents, risks people ask to accept, agents and tool servers to approve), and
// the decisions made.

import { Fragment, useId, useState, type ReactNode } from 'react';
import { Icon } from '../components/Icon';
import { toast } from '../components/toast';
import {
  AgentLink, Callout, Card, Chip, EmptyState, JsonBlock, PageHead, RefreshButton, TimeEl,
} from '../components/ui';
import { api } from '../lib/api';
import { refreshBadges, updateBadges } from '../lib/badges';
import { fmt, fullFmt, plural, relTime } from '../lib/format';
import { refresh, type PageDef } from '../lib/router';
import { can, isPerson, isScoped } from '../lib/session';
import { featureModes } from '../lib/shared';
import { statusMeta, toneOf } from '../lib/status';
import { assignmentButtons } from './accessPackages';
import { runLifecycle } from './agent';
import { PersonLink } from './ledger';
import { serverAction } from './toolservers';

type Approval = any;

interface ApprovalsData {
  tab: 'pending' | 'history';
  person: boolean;
  all: Approval[];
  agents: any[];
  mine: Approval[];
  asked: any[];
  packages: any[];
  inbox: any;
  approvalsMode: string | null | undefined;
}

export const approvalsPage: PageDef<ApprovalsData> = {
  re: /^\/approvals(?:\/(history))?$/,
  nav: 'approvals',
  title: 'Approvals',
  load: async ({ match }) => {
    const tab = match[1] === 'history' ? 'history' : 'pending';
    const person = isPerson();
    // Requests sent to the person signed in: agents acted for them.
    const [all, agents, mine, asked, packages, inbox] = await Promise.all([
      person ? api('v1/me/approvals') : api('v1/approvals'),
      person ? [] : api('v1/agents?include_deleted=true').catch(() => []),
      api('v1/me/approvals?status=pending').catch(() => []),
      person ? [] : api('v1/access-assignments?status=requested').catch(() => []),
      person ? [] : api('v1/access-packages').catch(() => []),
      // Everything else waiting for a decision this role can make.
      person ? null : api('v1/inbox').catch(() => null),
    ]);
    // The menu's count, as of what the page shows.
    updateBadges({ pendingApprovals: inbox ? inbox.total : all.filter((r: Approval) => r.status === 'pending').length });
    const approvalsMode = person ? 'enforce' : isScoped() ? null : (await featureModes().catch(() => ({} as Record<string, string>))).approvals;
    return { tab, person, all, agents, mine, asked, packages, inbox, approvalsMode };
  },
  View: ApprovalsView,
  titleOf: (data) => (data.tab === 'history' ? 'Approval history' : 'Approvals'),
};

function ApprovalsView({ data }: { data: ApprovalsData }) {
  const { tab, person, all, agents, mine, asked, packages, inbox, approvalsMode } = data;
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  const mineIds = new Set(mine.map((r) => r.id));
  const pending = all.filter((r) => r.status === 'pending');
  const history = all.filter((r) => r.status !== 'pending');
  const more: any[] = (inbox?.kinds || []).filter((k: any) => k.count && !['calls', 'access'].includes(k.kind));
  const waiting = pending.length + asked.length + more.reduce((n, k) => n + k.count, 0);
  const approval = (r: Approval) => <ApprovalCard key={r.id} r={r} agent={agentsById.get(r.agent_id)} mine={mineIds.has(r.id)} />;
  const tabs = (
    <nav className="tabs" aria-label="Approval views">
      <a className="tab" href="#/approvals" aria-current={tab === 'pending' ? 'page' : undefined}>
        Pending<span className="nav-badge" data-tone={waiting ? 'warning' : ''}>{fmt(waiting)}</span>
      </a>
      <a className="tab" href="#/approvals/history" aria-current={tab === 'history' ? 'page' : undefined}>
        History<span className="nav-badge">{fmt(history.length)}</span>
      </a>
    </nav>
  );
  let content: ReactNode;
  if (tab === 'pending') {
    // Yours first: requests agents made while acting for you wait for your decision.
    const yours = pending.filter((r) => mineIds.has(r.id));
    const others = pending.filter((r) => !mineIds.has(r.id));
    const sections: ReactNode[] = [];
    if (pending.length) {
      // Headed as one kind among others when there are others.
      if (asked.length || more.length) sections.push(<div key="calls" className="section-title"><h2>Calls held for a decision</h2></div>);
      sections.push(
        yours.length && !person ? <div key="yours-title" className="section-title"><h3>Waiting for you</h3></div> : null,
        yours.length ? <div key="yours" className="approval-list">{yours.map(approval)}</div> : null,
        yours.length && others.length ? <div key="others-title" className="section-title"><h3>{"Everyone else's"}</h3></div> : null,
        others.length ? <div key="others" className="approval-list">{others.map(approval)}</div> : null,
      );
    }
    if (asked.length) {
      sections.push(
        <Card key="access" title="Access requests" sub="Access packages asked for agents. Someone other than who asked decides.">
          <ul className="access-list" role="list">
            {asked.map((r) => (
              <li key={r.id} className="access-row">
                <div className="access-main">
                  <div className="cell-title">{r.package}{' for '}<AgentLink id={r.agent_id} name={r.agent_name} /></div>
                  <div className="cell-sub break">{`${r.requested_by}, for ${plural(r.days, 'day')}: ${r.reason} · `}<TimeEl iso={r.requested_at} /></div>
                </div>
                <div className="btn-row">
                  {assignmentButtons(r, packages, agentsById.get(r.agent_id) || { id: r.agent_id, name: r.agent_name })
                    .map((b, i) => <Fragment key={i}>{b}</Fragment>)}
                </div>
              </li>
            ))}
          </ul>
        </Card>,
      );
    }
    sections.push(...more.map((k) => <InboxCard key={k.kind} k={k} />));
    content = sections.length ? (
      <div className="stack">{sections}</div>
    ) : (
      <section className="card">
        {person
          ? <EmptyState title="Nothing is waiting for you" text="When an agent acting for you needs your approval to do something, it appears here." />
          : (
            <EmptyState
              title="Nothing is waiting for a decision"
              text="Calls policy holds for a person, access asked for agents, risks people ask to accept, and agents and tool servers registered for review appear here."
            />
          )}
      </section>
    );
  } else {
    content = (
      <section className="card" aria-label="Approval history">
        {history.length ? <ApprovalHistoryTable rows={history} /> : <EmptyState title="No decided approvals yet" />}
      </section>
    );
  }
  return (
    <div className="page">
      <PageHead
        title="Approvals"
        sub={person
          ? 'What agents acting for you want to do, and need you to approve first. Approve a call and the agent can make it once.'
          : 'Everything waiting for a decision you can make: calls policy held, access asked for agents, risks people ask to accept, and agents and tool servers to approve. An approved call is single-use: the agent retries the identical call and it goes through once.'}
        actions={[<RefreshButton key="refresh" />]}
      />
      {approvalsMode && approvalsMode !== 'enforce' ? (
        <Callout tone="warning" icon="eye">
          <span>
            <strong>{`Human approval is ${approvalsMode === 'off' ? 'off' : 'in monitor mode'}: `}</strong>
            {approvalsMode === 'off' ? 'no call waits for approval. ' : 'calls that need approval go through, and the ledger records them. '}
            <a href="#/features">Features</a>{'.'}
          </span>
        </Callout>
      ) : null}
      {tabs}
      {content}
    </div>
  );
}

// One kind of decision from the inbox (GET /v1/inbox), beyond calls and access requests.
function InboxCard({ k }: { k: any }) {
  // Its count is of agents, its rows of platforms.
  const listed = k.kind === 'platform_agents' ? k.count : k.items.length;
  const more = k.count > listed ? <p className="hint">{`And ${fmt(k.count - listed)} more.`}</p> : null;
  const row = (key: number, main: ReactNode, sub: ReactNode, buttons: ReactNode) => (
    <li key={key} className="access-row">
      <div className="access-main"><div className="cell-title">{main}</div>{sub ? <div className="cell-sub break">{sub}</div> : null}</div>
      {buttons ? <div className="btn-row">{buttons}</div> : null}
    </li>
  );
  const list = (rows: ReactNode[]) => <div><ul className="access-list" role="list">{rows}</ul>{more}</div>;
  if (k.kind === 'risks') {
    return (
      <Card
        title={k.title}
        sub="The people an issue reached ask for its risk to be accepted until a date, and say why. Accept or decline it on the issue; nobody accountable for the agent accepts its risk."
      >
        {list(k.items.map((f: any, i: number) => row(
          i,
          <a href={`#/findings/${encodeURIComponent(f.id)}`}>{f.title}</a>,
          <>
            {f.agent_id ? <><AgentLink id={f.agent_id} name={f.agent_name || f.subject} />{' · '}</> : null}
            {`${f.asked.by}, until ${String(f.asked.until).slice(0, 10)}: ${f.asked.reason}`}
          </>,
          <a className="btn btn--sm" href={`#/findings/${encodeURIComponent(f.id)}`}>Decide</a>,
        )))}
      </Card>
    );
  }
  if (k.kind === 'agents') {
    return (
      <Card title={k.title} sub="Registered for review. Approved, an agent becomes active and can authenticate; blocked, it can do nothing.">
        {list(k.items.map((a: any, i: number) => row(
          i,
          <AgentLink id={a.id} name={a.name} />,
          <>
            {`Owner ${a.owner || 'none'} · sponsors ${(a.sponsors || []).join(', ') || 'none'}`}{a.blueprint ? ` · blueprint ${a.blueprint}` : null}
            {` · registered by ${a.created_by || 'someone'} `}<TimeEl iso={a.created_at} />
          </>,
          <>
            <button type="button" className="btn btn--sm btn--primary" onClick={() => runLifecycle(a, 'approve')}><Icon name="check" />Approve</button>
            <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => runLifecycle(a, 'block')}><Icon name="ban" />Block</button>
          </>,
        )))}
      </Card>
    );
  }
  if (k.kind === 'toolservers') {
    return (
      <Card title={k.title} sub="Registered for review. Approved, agents whose grants cover it can call its tools through the gateway.">
        {list(k.items.map((ts: any, i: number) => row(
          i,
          ts.name,
          <>
            <code>{ts.url}</code>{ts.owner ? ` · owner ${ts.owner}` : null}{` · registered by ${ts.created_by || 'someone'} `}<TimeEl iso={ts.created_at} />
          </>,
          <>
            <button type="button" className="btn btn--sm btn--primary" onClick={() => serverAction(ts, 'approve')}><Icon name="check" />Approve</button>
            <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => serverAction(ts, 'block')}><Icon name="ban" />Block</button>
          </>,
        )))}
      </Card>
    );
  }
  if (k.kind === 'definitions') {
    return (
      <Card title={k.title} sub="Calls to these tools are refused until an administrator reads the new definition and approves it, in the tool server's catalog.">
        {list(k.items.map((d: any, i: number) => row(
          i,
          <code>{`${d.server}/${d.tool}`}</code>,
          <>{'Changed '}<TimeEl iso={d.since} /></>,
          <a className="btn btn--sm" href="#/toolservers">Review</a>,
        )))}
      </Card>
    );
  }
  if (k.kind === 'platform_agents') {
    return (
      <Card title={k.title} sub="Found on the platforms AgentGov reads, with no owner, sponsors or review yet. Adopt the ones you keep; block or delete the others where they run.">
        {list(k.items.map((p: any, i: number) => row(
          i,
          `${plural(p.count, 'agent')} in ${p.platform}`,
          null,
          <a className="btn btn--sm" href="#/agents?status=discovered">Review them</a>,
        )))}
      </Card>
    );
  }
  return null;
}

function ApprovalCard({ r, agent, mine = false }: { r: Approval; agent: any; mine?: boolean }) {
  const noteId = `note-${r.id}`;
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const headingId = `approval${useId().replace(/:/g, '')}`;
  const decide = async (verdict: 'approve' | 'deny') => {
    setBusy(true);
    const text = note.trim();
    try {
      await api(`v1/approvals/${encodeURIComponent(r.id)}/${verdict}`, { method: 'POST', body: text ? { note: text } : {} });
      toast(verdict === 'approve'
        ? `Approved ${r.resource}. ${r.agent_name} can retry the call once.`
        : `Denied ${r.resource} for ${r.agent_name}.`);
      void refreshBadges();
      await refresh();
      // Drawn again, its buttons are ready again.
      setBusy(false);
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
      setBusy(false);
    }
  };
  const agentWarning = agent && agent.status !== 'active' ? (
    <Callout tone={toneOf('agent', agent.status)} icon="info">
      <span>
        <strong>{`${agent.name} is ${statusMeta('agent', agent.status)[2].toLowerCase()}. `}</strong>
        Policy denies its calls before approvals are checked, so approving changes nothing unless the agent becomes active before the request expires.
      </span>
    </Callout>
  ) : null;
  // The person it was sent to decides it, or approvers; administrators can always decide.
  const forPerson = r.deciders === 'person';
  const mayDecide = can('admin', agent) || (forPerson ? mine : can('approve', agent) || can('decide', agent));
  const deciders = forPerson ? (mine ? 'You decide this request.' : `${r.on_behalf_of} decides this request.`) : 'An approver or admin decides this request.';
  return (
    <section className="card approval" aria-labelledby={headingId} tabIndex={-1}>
      <div className="card-head">
        <div className="card-head-text">
          <h2 id={headingId} className="resource">{r.resource}</h2>
          <p className="card-sub">
            {`${r.action} requested by `}{isPerson() ? r.agent_name : <AgentLink id={r.agent_id} name={r.agent_name} />}
            {r.on_behalf_of ? <>{' for '}{mine ? 'you' : isPerson() ? r.on_behalf_of : <PersonLink name={r.on_behalf_of} />}</> : null}
            {' · '}<TimeEl iso={r.requested_at} />
          </p>
        </div>
        <div className="chip-row">
          <Chip kind="approval" value={r.status} />
          <span className="chip chip--plain" title={r.expires_at ? fullFmt.format(new Date(r.expires_at)) : undefined}>
            <Icon name="clock" />{`Expires ${r.expires_at ? relTime(r.expires_at) : 'never'}`}
          </span>
        </div>
      </div>
      <div className="card-body">
        {agentWarning}
        <div className="approval-grid">
          <div className="stack" style={{ gap: 8 }}>
            <span className="field-label">Why it was held</span>
            {(r.reasons || []).length ? (
              <ul className="reasons" role="list">
                {r.reasons.map((reason: string, i: number) => <li key={i}><Icon name="user-check" /><span>{reason}</span></li>)}
              </ul>
            ) : <p className="muted small">No reason recorded.</p>}
          </div>
          <div className="stack" style={{ gap: 8 }}>
            <span className="field-label">Arguments (redacted)</span>
            <JsonBlock value={r.arguments ?? {}} />
          </div>
        </div>
        {forPerson && !mine && mayDecide ? (
          <Callout tone="neutral" icon="info">
            {`${r.on_behalf_of}, whom the agent acted for, decides this request. As an administrator, you can decide it instead.`}
          </Callout>
        ) : null}
        {mayDecide ? (
          <div className="decide">
            <div className="field">
              <label htmlFor={noteId}>{'Note for the ledger '}<span className="muted">(optional)</span></label>
              <textarea id={noteId} rows={1} placeholder="For example: confirmed with the customer" value={note} onChange={(e) => setNote(e.target.value)} />
            </div>
            <div className="btn-row">
              <button type="button" className="btn btn--danger-quiet" disabled={busy} onClick={() => decide('deny')}><Icon name="ban" />Deny</button>
              <button type="button" className="btn btn--primary" disabled={busy} onClick={() => decide('approve')}><Icon name="check" />Approve</button>
            </div>
          </div>
        ) : <p className="muted small">{deciders}</p>}
      </div>
    </section>
  );
}

function ApprovalHistoryTable({ rows }: { rows: Approval[] }) {
  const dash = <span className="muted">—</span>;
  return (
    <div className="table-wrap">
      <table className="data rtable">
        <thead>
          <tr>{['Outcome', 'Tool call', 'Agent', 'For', 'Decided by', 'Decided', 'Note', 'Requested'].map((t) => <th key={t} scope="col">{t}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td data-label="Outcome"><Chip kind="approval" value={r.status} title={r.used_at ? `Used ${fullFmt.format(new Date(r.used_at))}` : null} /></td>
              <td data-label="Tool call"><span className="resource">{r.resource}</span></td>
              <td data-label="Agent" className="break">{isPerson() ? r.agent_name : <AgentLink id={r.agent_id} name={r.agent_name} />}</td>
              <td data-label="For" className="break">{r.on_behalf_of ? (isPerson() ? r.on_behalf_of : <PersonLink name={r.on_behalf_of} />) : dash}</td>
              <td data-label="Decided by" className="break">{r.decided_by || <span className="muted">{r.status === 'expired' ? 'Nobody (expired)' : '—'}</span>}</td>
              <td data-label="Decided" className="nowrap"><TimeEl iso={r.decided_at} /></td>
              <td data-label="Note" className="break">{r.decision_note || dash}</td>
              <td data-label="Requested" className="nowrap"><TimeEl iso={r.requested_at} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
