// One issue: what it is, who it goes to, its tickets and messages, what happened to it, and
// what can be done about it.

import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { AgentLink, Callout, Card, Chip, EmptyState, Facts, PageHead, PlainChip, RefreshButton, TimeEl } from '../components/ui';
import { api } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { fmt, humanize } from '../lib/format';
import { refresh, type PageDef, type PageProps } from '../lib/router';
import { can, isPerson } from '../lib/session';
import { assignmentAction, requestPackage, reviewAssignment } from './accessPackages';
import { answerIssue, exceptionAsked, FINDING_DONE, findingActions } from './findings';

type Finding = any;

interface FindingData {
  f: Finding;
  // An issue about an access package: its assignment, and the packages there are.
  access: { row: any; packages: any[] } | null;
}

async function accessOf(f: Finding): Promise<FindingData['access']> {
  const row = await api(`v1/access-assignments/${encodeURIComponent(f.subject)}`).catch(() => null);
  if (!row) return null;
  const packages = await api<any[]>('v1/access-packages').catch(() => []);
  return { row, packages };
}

export const findingPage: PageDef<FindingData> = {
  re: /^\/findings\/([^/]+)$/,
  nav: 'findings',
  title: 'Issue',
  load: async ({ match }) => {
    const id = decodeURIComponent(match[1]);
    const f = await api(`v1/findings/${encodeURIComponent(id)}`);
    return { f, access: f.type.startsWith('access.') ? await accessOf(f) : null };
  },
  View: FindingView,
  titleOf: (data) => data.f.title,
};

function FindingView({ data }: PageProps<FindingData>) {
  const { f } = data;
  const person = isPerson();
  const act = guarded(async (action: string) => {
    const answered = await answerIssue(f, action);
    if (answered === false) return;
    if (answered === null) {
      await api(`v1/findings/${encodeURIComponent(f.id)}/${action}`, { method: 'POST' });
      toast(`${FINDING_DONE[action]}: ${f.title}`);
    }
    void refreshBadges();
    await refresh();
  });
  const subject = f.agent_id && !person ? <AgentLink id={f.agent_id} name={f.agent_name || f.subject} /> : <code>{f.agent_name || f.subject}</code>;
  const crumbs = (
    <nav className="crumbs" aria-label="Breadcrumb">
      <a href="#/findings">{person ? 'Your issues' : 'Issues'}</a><Icon name="chevron" /><span aria-current="page">{f.type}</span>
    </nav>
  );
  const dismissal = f.details?.dismissal;
  return (
    <div className="page">
      <PageHead title={f.title} crumbs={crumbs} actions={[<RefreshButton key="refresh" />]} />
      <div className="chip-row">
        <Chip kind="severity" value={f.severity} />
        <Chip kind="finding" value={f.status} />
        <PlainChip text={humanize(f.category)} />
        {f.verified === false ? <PlainChip text="Unverified" tone="warning" iconName="triangle" /> : null}
      </div>
      {f.verified === false ? (
        <Callout tone="warning" icon="triangle">
          <span>
            <strong>{'Unverified: '}</strong>
            {`${f.unverified_reason || 'the latest sync that checks it failed'}, so it may no longer hold. It stays open until its check runs again.`}
          </span>
        </Callout>
      ) : null}
      {exceptionAsked(f, act)}
      <Card title="What it is">
        <div className="stack">
          {f.description ? <p>{f.description}</p> : null}
          {f.remediation ? <p className="finding-fix"><strong>{'How to fix: '}</strong>{f.remediation}</p> : null}
          <Facts rows={[
            ['Subject', <span>{subject}</span>],
            ['Seen', (
              <span>
                {`${f.occurrences === 1 ? 'once' : `${fmt(f.occurrences)} times`}, first `}<TimeEl iso={f.first_seen} />{', last '}<TimeEl iso={f.last_seen} />
              </span>
            )],
            f.status === 'accepted' ? ['Risk accepted until', (
              <span><TimeEl iso={f.accepted_until} absolute />{f.accepted_reason ? `: ${f.accepted_reason}` : ''}</span>
            )] : null,
            f.status === 'dismissed' && dismissal ? ['Dismissed because', (
              <span>
                {dismissal.reason}
                {dismissal.until ? <>{' (until '}<TimeEl iso={dismissal.until} absolute />{')'}</> : ''}
              </span>
            )] : null,
            f.acknowledged_at ? ['Acknowledged', <span>{`by ${f.acknowledged_by} `}<TimeEl iso={f.acknowledged_at} /></span>] : null,
            f.resolved_at && f.status !== 'open' ? [humanize(f.status), <span>{`by ${f.resolved_by || 'unknown'} `}<TimeEl iso={f.resolved_at} /></span>] : null,
          ]} />
          <div className="btn-row">{findingActions(f, act, { yours: f.yours, detail: true })}</div>
        </div>
      </Card>
      {data.access ? <FindingAccessCard f={f} row={data.access.row} packages={data.access.packages} /> : null}
      <FindingAttestCard f={f} />
      <ChainCard f={f} />
      <TicketsCard f={f} />
      <NotificationsCard f={f} />
      <HistoryCard f={f} />
    </div>
  );
}

// An issue that an agent's review is due: its sponsors attest it from here, whatever their
// role (the people the issue reached see this page, not the agent's).
function FindingAttestCard({ f }: { f: Finding }) {
  if (!f.type.startsWith('agent.attestation') || !f.agent_id || f.status !== 'open') return null;
  if (!f.yours && !can('admin', f)) return null;
  const attest = guarded(async () => {
    const values = await ask({
      title: 'Attest this agent?',
      text: 'Confirm that it is still needed and that its access is still right. Its sponsors do this.',
      iconName: 'shield-check', confirm: 'Attest',
      fields: [{ id: 'note', label: 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
    });
    if (!values) return;
    const updated = await api(`v1/agents/${encodeURIComponent(f.agent_id)}/attest`, { method: 'POST', body: values.note ? { note: values.note } : {} });
    const due = updated.attestation?.expires_at;
    toast(due ? `Attested: reviewed again on ${due.slice(0, 10)}. The issue closes at the next check.` : 'Attested. The issue closes at the next check.');
  });
  return (
    <Card title="Is it still needed?">
      <div className="stack">
        <p>{'One of its sponsors confirms that it is still needed and that its access is still right. If it isn\'t needed, say so to an administrator, who deletes it.'}</p>
        <div className="btn-row">
          <button type="button" className="btn btn--primary btn--sm" onClick={attest}><Icon name="shield-check" />Attest</button>
        </div>
      </div>
    </Card>
  );
}

// An issue about an access package: what it is, and renewing, keeping or removing it.
function FindingAccessCard({ f, row, packages }: { f: Finding; row: any; packages: any[] }) {
  const pk = packages.find((x) => x.name === row.package);
  const agent = { id: row.agent_id, name: row.agent_name };
  const held = ['active', 'expired'].includes(row.status);
  // Renewing, keeping, removing or revoking it: what fails says so; what is done shows.
  const act = (run: () => Promise<unknown>) => guarded(async () => {
    if (await run()) {
      void refreshBadges();
      await refresh();
    }
  });
  const buttons = held ? [
    pk && f.type !== 'access.review_due' ? (
      <button key="renew" type="button" className="btn btn--sm btn--primary" onClick={act(() => requestPackage(agent, packages, pk))}>
        <Icon name="refresh" />Renew
      </button>
    ) : null,
    f.type === 'access.review_due' ? (
      <button key="keep" type="button" className="btn btn--sm btn--primary" onClick={act(() => reviewAssignment(row, true))}>
        <Icon name="check" />Keep it
      </button>
    ) : null,
    f.type === 'access.review_due' ? (
      <button key="remove" type="button" className="btn btn--sm btn--danger-quiet" onClick={act(() => reviewAssignment(row, false))}>
        <Icon name="ban" />Remove it
      </button>
    ) : null,
    can('approve', f) || can('contain', f) ? (
      <button key="revoke" type="button" className="btn btn--sm btn--danger-quiet" onClick={act(() => assignmentAction(row, 'revoke'))}>
        <Icon name="ban" />Revoke
      </button>
    ) : null,
  ].filter(Boolean) : [];
  return (
    <Card title="Access package">
      <div className="stack">
        <Facts rows={[
          ['Package', <span>{row.package}{' '}<Chip kind="access" value={row.status} /></span>],
          ['Agent', isPerson() ? row.agent_name : <AgentLink id={row.agent_id} name={row.agent_name} />],
          row.expires_at ? ['Expires', <TimeEl iso={row.expires_at} absolute />] : null,
          ['Asked for by', `${row.requested_by}: ${row.reason}`],
          pk ? ['Grants', [
            ...pk.permissions.map((g: any) => `${g.server}: ${g.tools.join(', ')}`),
            ...pk.model_access.map((m: any) => `${m.provider}: ${m.models.join(', ')}`),
            ...pk.agent_access.map((x: any) => `agent ${x}`),
          ].join('; ')] : null,
        ]} />
        {buttons.length ? <div className="btn-row">{buttons}</div> : null}
      </div>
    </Card>
  );
}

function ChainCard({ f }: { f: Finding }) {
  const steps: any[] = f.chain || [];
  const body = steps.length ? (
    <ol className="levels">
      {steps.map((step, i) => (
        <li key={i} data-reached={step.reached ? 'true' : 'false'} aria-current={step.current ? 'step' : undefined}>
          <Icon name={step.current ? 'user' : step.reached ? 'check-circle' : 'minus'} />
          <div>
            <strong>{humanize(step.level)}</strong>
            <div className="cell-sub break">{step.who.join(', ')}</div>
            {step.current && f.status === 'open' && f.escalate_at && !f.acknowledged_at ? (
              <div className="cell-sub">{'Goes to the next step '}<TimeEl iso={f.escalate_at} />{' unless someone acknowledges it'}</div>
            ) : null}
          </div>
        </li>
      ))}
    </ol>
  ) : (
    <EmptyState title="Nobody to send it to" text="Give the agent an owner or sponsors, or mark a team as the default team: issues with nobody else go to it." />
  );
  return (
    <Card
      title="Who it goes to"
      sub={'Step by step, until someone acknowledges it: an agent\'s owner, then its sponsors, then its team. Each step is told by email and in its team\'s chat.'}
    >
      {body}
    </Card>
  );
}

// Its tickets in the service desks, and how each stands there.
function TicketsCard({ f }: { f: Finding }) {
  const rows: any[] = f.tickets || [];
  if (!rows.length) return null;
  return (
    <Card
      title="Tickets"
      sub="In your service desks: AgentGov keeps each in step with the issue, and reads back what happens to it there. Taking a ticket on there takes the issue on."
      flush
    >
      <div className="table-wrap">
        <table className="data rtable">
          <caption className="sr-only">Tickets</caption>
          <thead><tr>{['Ticket', 'There', 'AgentGov'].map((t) => <th key={t} scope="col">{t}</th>)}</tr></thead>
          <tbody>
            {rows.map((t, i) => (
              <tr key={i}>
                <td data-label="Ticket" className="break">
                  {t.url && t.key
                    ? <a href={t.url} target="_blank" rel="noopener" className="cell-title">{t.key}{' '}<Icon name="external" /></a>
                    : <span className="cell-title">{t.key || 'Not opened yet'}</span>}
                  <div className="cell-sub">{`${t.desk}${t.team ? `, team ${t.team}` : ''}`}</div>
                  {t.replaces ? <div className="cell-sub">{`Takes over from ${t.replaces}`}</div> : null}
                </td>
                <td data-label="There">
                  {t.state ? <span>{t.state}</span> : <span className="muted">—</span>}
                  {t.assignee ? <div className="cell-sub">{t.assignee}</div> : null}
                  {t.synced_at ? <div className="cell-sub">{'Read '}<TimeEl iso={t.synced_at} /></div> : null}
                </td>
                <td data-label="AgentGov">
                  <Chip kind="ticket" value={t.status} />
                  {t.last_error ? <div className="cell-sub break">{t.last_error}</div> : null}
                  {t.next_attempt_at && t.attempts ? <div className="cell-sub">{'Tries again '}<TimeEl iso={t.next_attempt_at} /></div> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function NotificationsCard({ f }: { f: Finding }) {
  const rows: any[] = f.notifications || [];
  if (!rows.length) return null;
  return (
    <Card title="Messages" sub="Emails and chat messages about it, retried until they go." flush>
      <div className="table-wrap">
        <table className="data rtable">
          <caption className="sr-only">Messages</caption>
          <thead><tr>{['To', 'Step', 'Status'].map((t) => <th key={t} scope="col">{t}</th>)}</tr></thead>
          <tbody>
            {rows.map((n, i) => (
              <tr key={i}>
                <td data-label="To" className="break">
                  <span className="cell-title">{n.recipient}</span>
                  <div className="cell-sub">{n.channel === 'email' ? 'Email' : humanize(n.channel)}</div>
                </td>
                <td data-label="Step">{humanize(n.level)}</td>
                <td data-label="Status">
                  <Chip kind="notification" value={n.status} />
                  {n.sent_at ? <div className="cell-sub"><TimeEl iso={n.sent_at} /></div> : null}
                  {n.last_error ? <div className="cell-sub break">{n.last_error}</div> : null}
                  {n.next_attempt_at && n.attempts ? <div className="cell-sub">{'Tries again '}<TimeEl iso={n.next_attempt_at} /></div> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

// What happened to an issue, in the words its page uses rather than its ledger's.
const HISTORY_WORDS: Record<string, string> = {
  exception_requested: 'Risk acceptance asked',
  exception_declined: 'Risk acceptance declined',
  declined: "Said it isn't theirs",
};

function HistoryCard({ f }: { f: Finding }) {
  const rows: any[] = f.history || [];
  if (!rows.length) return null;
  return (
    <Card title="History" sub="From the evidence ledger, newest first.">
      <ul className="timeline" role="list">
        {rows.map((e, i) => {
          const what = e.type.replace(/^finding\./, '');
          return (
            <li key={i}>
              <div className="cell-title">{HISTORY_WORDS[what] || humanize(what)}</div>
              <div className="cell-sub break">
                {e.actor}{' · '}<TimeEl iso={e.ts} />
                {e.details?.to ? ` · to ${e.details.to}` : ''}
                {e.details?.ticket ? ` · ${e.details.desk ? `${e.details.desk} ` : ''}${e.details.ticket}` : ''}
                {e.details?.why ? ` · ${e.details.why}` : ''}
                {e.details?.outcome ? ` · ${e.details.outcome}` : ''}
                {e.details?.assignees ? ` · ${e.details.assignees.join(', ')}` : ''}
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
