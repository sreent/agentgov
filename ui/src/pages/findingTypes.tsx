// Which types of issues are raised here, and how severe each is (docs/issues.md).

import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, Chip, EmptyState, PageHead, PlainChip, RefreshButton, TimeEl } from '../components/ui';
import { api } from '../lib/api';
import { fmt, plural } from '../lib/format';
import { refresh, type PageDef, type PageProps } from '../lib/router';
import { can, isPerson } from '../lib/session';
import { SEVERITY_ORDER, statusMeta } from '../lib/status';
import { findingTabs } from './findings';

type FindingType = any;

export const findingTypesPage: PageDef<FindingType[] | null> = {
  re: /^\/findings\/types$/,
  nav: 'findings',
  title: 'Issue types',
  orgWide: true,
  load: async () => {
    if (isPerson()) {
      window.location.replace('#/findings');
      return null;
    }
    return api<FindingType[]>('v1/finding-types');
  },
  View: FindingTypesView,
};

function FindingTypesView({ data: types }: PageProps<FindingType[] | null>) {
  if (!types) return <div />;
  const admin = can('admin');
  const off = types.filter((t) => t.mode === 'off');
  const body = types.length ? (
    <div className="table-wrap">
      <table className="data rtable">
        <caption className="sr-only">Types of issues</caption>
        <thead>
          <tr>{['Type', 'Raised', 'Severity', 'Open', ''].map((t, i) => <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>)}</tr>
        </thead>
        <tbody>
          {types.map((t) => (
            <tr key={t.type} data-type={t.type}>
              <td data-label="Type" className="break">
                <span className="cell-title mono">{t.type}</span>
                {t.changed_by ? <div className="cell-sub">{`Set by ${t.changed_by.replace(/^[a-z]+:/, '')} `}<TimeEl iso={t.changed_at} /></div> : null}
              </td>
              <td data-label="Raised">
                {t.mode === 'off'
                  ? <PlainChip text="Off" tone="warning" iconName="minus" title="Checked, but what it finds is kept dismissed" />
                  : <PlainChip text="On" tone="good" iconName="check-circle" />}
              </td>
              <td data-label="Severity">{t.severity ? <Chip kind="severity" value={t.severity} /> : <span className="muted">{"Its checks' own"}</span>}</td>
              <td data-label="Open">{`${fmt(t.open)} of ${fmt(t.total)}`}</td>
              <td data-label="">
                {admin ? <button type="button" className="btn btn--sm" onClick={guarded(() => findingTypeForm(t))}><Icon name="edit" />Change</button> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <EmptyState title="No issues yet" text="A type is listed once AgentGov raises an issue of it, or once it is set up here." />
  );
  return (
    <div className="page">
      <PageHead
        title="Issues"
        sub="Each type of issue AgentGov's checks raise. Turn off the types your organisation doesn't act on: they are still checked, but what they find is kept dismissed and reaches no one. Or say how severe a type is here."
        actions={[
          admin ? (
            <button key="add" type="button" className="btn btn--primary" onClick={guarded(() => findingTypeForm(null))}><Icon name="plus" />Set up a type</button>
          ) : null,
          <RefreshButton key="refresh" />,
        ]}
      />
      {findingTabs('types')}
      {off.length ? (
        <Callout tone="neutral" icon="info">
          <span>
            <strong>{`${plural(off.length, 'type')} off: `}</strong>
            {off.length === 1
              ? 'what it finds is kept dismissed. Turned on again, what its checks find again comes back the next time they run.'
              : 'what they find is kept dismissed. Turned on again, what their checks find again comes back the next time they run.'}
          </span>
        </Callout>
      ) : null}
      <Card title="Types of issues" flush={Boolean(types.length)}>{body}</Card>
    </div>
  );
}

async function findingTypeForm(t: FindingType | null) {
  const saved = await ask<any>({
    title: t ? `Issue type ${t.type}` : 'Set up a type of issue',
    text: t ? 'Changes are recorded in the evidence ledger.' : 'Set up a type before its checks raise anything, such as agent.no_owner (docs/issues.md lists them). Changes are recorded in the evidence ledger.',
    iconName: 'edit', confirm: 'Save',
    fields: [
      t ? null : { id: 'type', label: 'Type', required: true, mono: true, placeholder: 'agent.no_owner' },
      {
        id: 'mode', label: 'Raised', type: 'select', value: t?.mode || 'on',
        options: [
          { value: 'on', label: 'On: raised and sent to the people responsible' },
          { value: 'off', label: 'Off: checked, but what it finds is kept dismissed' },
        ],
        hint: 'Turned off, its open issues are dismissed.',
      },
      {
        id: 'severity', label: 'Severity', type: 'select', value: t?.severity || '',
        options: [{ value: '', label: "Its checks' own" }, ...SEVERITY_ORDER.map((k) => ({ value: k, label: statusMeta('severity', k)[2] }))],
        hint: 'For what it finds from now on, and what it found that is still open.',
      },
    ],
    submit: (v) => api(`v1/finding-types/${encodeURIComponent(t ? t.type : v.type)}`, {
      method: 'PUT', body: { mode: v.mode, severity: v.severity || null },
    }),
  });
  if (!saved) return;
  toast(`${saved.type}: ${saved.mode === 'off' ? 'off' : 'on'}, ${saved.severity ? `severity ${saved.severity}` : "its checks' severity"}.`);
  await refresh();
}
