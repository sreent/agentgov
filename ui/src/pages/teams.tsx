// Teams: who owns agents (as an agent's owner or sponsor), and takes the issues about them
// that their owners and sponsors didn't acknowledge in time; where each is reached.

import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, EmptyState, PageHead, PlainChip, RefreshButton } from '../components/ui';
import { api } from '../lib/api';
import { humanize } from '../lib/format';
import { parseList } from '../lib/forms';
import { refresh, type PageDef, type PageProps } from '../lib/router';
import { can, isPerson } from '../lib/session';
import { NAME_HINT } from '../lib/shared';

type Team = any;

interface TeamsData {
  teams: Team[];
  // The destinations that are chats (Teams or Slack): where a team's issues may be posted.
  chats: any[];
}

export const teamsPage: PageDef<TeamsData | null> = {
  re: /^\/findings\/teams$/,
  nav: 'teams',
  title: 'Teams',
  load: async () => {
    if (isPerson()) {
      window.location.replace('#/findings');
      return null;
    }
    const [teams, destinations] = await Promise.all([api<Team[]>('v1/teams'), api<any[]>('v1/destinations').catch(() => [])]);
    return { teams, chats: destinations.filter((d) => ['teams', 'slack'].includes(d.kind)) };
  },
  View: TeamsView,
};

function TeamsView({ data }: PageProps<TeamsData | null>) {
  if (!data) return <div />;
  const { teams, chats } = data;
  const admin = can('admin');
  const hasDefault = teams.some((t) => t.default);
  const body = teams.length ? (
    <div className="table-wrap">
      <table className="data rtable">
        <caption className="sr-only">Teams</caption>
        <thead>
          <tr>{['Team', 'Members', 'Reached at', ''].map((t, i) => <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>)}</tr>
        </thead>
        <tbody>
          {teams.map((t) => {
            const emailed = t.members.some((m: string) => m.includes('@'));
            return (
              <tr key={t.name} data-team={t.name}>
                <td data-label="Team" className="break">
                  <span className="cell-title">{t.name}</span>
                  {t.default ? <div><PlainChip text="Default team" tone="good" iconName="check-circle" /></div> : null}
                  {t.description ? <div className="cell-sub">{t.description}</div> : null}
                </td>
                <td data-label="Members" className="break">{t.members.length ? t.members.join(', ') : <span className="muted">None</span>}</td>
                <td data-label="Reached at" className="break">
                  {t.emails.length ? <div>{t.emails.join(', ')}</div> : emailed ? <div className="cell-sub">{"Its members' email addresses"}</div> : null}
                  {t.destinations.length ? (
                    <div className="chip-row">{t.destinations.map((d: string) => <PlainChip key={d} text={d} iconName="secops" />)}</div>
                  ) : null}
                  {!t.emails.length && !t.destinations.length && !emailed ? <span className="muted">In AgentGov only</span> : null}
                </td>
                <td data-label="">
                  {admin ? (
                    <div className="btn-row">
                      <button type="button" className="btn btn--sm" onClick={guarded(() => teamForm(t, chats))}><Icon name="edit" />Edit</button>
                      <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => deleteTeam(t))}><Icon name="trash" />Delete</button>
                    </div>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  ) : (
    <EmptyState title="No teams" text="Add the teams that own agents, and the one that takes the issues nobody else does." />
  );
  return (
    <div className="page">
      <PageHead
        title="Teams"
        sub="Teams own agents (as an agent's owner or sponsor), and take the issues about them that their owners and sponsors didn't acknowledge in time."
        actions={[
          admin ? (
            <button key="add" type="button" className="btn btn--primary" onClick={guarded(() => teamForm(null, chats))}><Icon name="plus" />Add team</button>
          ) : null,
          <RefreshButton key="refresh" />,
        ]}
      />
      {teams.length && !hasDefault ? (
        <Callout tone="warning" icon="alert-circle">
          <span>
            <strong>{'No default team: '}</strong>
            issues about agents without a team of their own, and those that are about nothing else, go to nobody. Mark one team as the default.
          </span>
        </Callout>
      ) : null}
      <Card title="Teams" flush={Boolean(teams.length)}>{body}</Card>
    </div>
  );
}

async function teamForm(t: Team | null, chats: any[]) {
  const editing = Boolean(t);
  const saved = await ask<any>({
    title: editing ? `Edit team ${t.name}` : 'Add a team',
    text: 'Agents name it as their owner, a sponsor or their team, and blueprints as their agents\' team. Changes are recorded in the evidence ledger.',
    iconName: editing ? 'edit' : 'user', confirm: editing ? 'Save changes' : 'Add team', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'cx-platform', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', value: t?.description || '' },
      {
        id: 'members', label: 'Members', type: 'textarea', value: (t?.members || []).join(', '), placeholder: 'alice@example.com, bob@example.com',
        hint: 'Email addresses or user names, separated by commas: they see the team\'s issues in AgentGov and acknowledge them.',
      },
      {
        id: 'emails', label: 'Email its issues to', value: (t?.emails || []).join(', '), placeholder: 'cx-platform@example.com',
        hint: "A list's or a shared mailbox's address, or people's own. Empty: its members' addresses. Needs a mail server (AGENTGOV_SMTP_URL).",
      },
      chats.length ? { type: 'section', label: 'Post its issues to' } : null,
      ...chats.map((d) => ({ id: `chat-${d.name}`, label: `${d.name} (${humanize(d.kind)})`, type: 'checkbox' as const, value: (t?.destinations || []).includes(d.name) })),
      { id: 'default', label: 'The default team: it takes the issues that have no team of their own', type: 'checkbox', value: Boolean(t?.default) },
    ],
    extra: chats.length ? null : <p className="hint">To post its issues in a Teams or Slack channel, add the channel as a destination on the Security operations page first.</p>,
    submit: (v) => {
      const body = {
        description: v.description, members: parseList(v.members), emails: parseList(v.emails),
        destinations: chats.filter((d) => v[`chat-${d.name}`]).map((d) => d.name), default: v.default,
      };
      if (editing) return api(`v1/teams/${encodeURIComponent(t.name)}`, { method: 'PATCH', body, ifMatch: t.version });
      return api('v1/teams', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved team ${saved.name}.` : `Added team ${saved.name}.`);
  await refresh();
}

async function deleteTeam(t: Team) {
  const done = await ask({
    title: `Delete team ${t.name}?`,
    text: 'Teams that blueprints or agents name cannot be deleted: name another team or person there first.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete team', busy: 'Deleting…',
    submit: () => api(`v1/teams/${encodeURIComponent(t.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted team ${t.name}.`);
  await refresh();
}
