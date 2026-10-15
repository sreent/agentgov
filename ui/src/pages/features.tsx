// Features: which parts of AgentGov are used, and how strictly; what AgentGov can reach;
// starting points that set many modes at once; and exceptions for some agents.

import { Fragment, type ReactNode } from 'react';
import { ask } from '../components/dialog';
import { useSynced } from '../components/hooks';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, Chip, Facts, PageHead, PlainChip, RefreshButton, TimeEl, type FactRow } from '../components/ui';
import { ApiError, api } from '../lib/api';
import { humanize, plural } from '../lib/format';
import { parseLabels, parseList } from '../lib/forms';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { MODE_WORDS } from '../lib/shared';
import { ruleScope } from './rules';

type Feature = any;
type Preset = any;

// Whether a feature can do what its mode says (agentgov.health): words and tone.
const FEATURE_STATUS: Record<string, [words: string, tone: string, iconName: string]> = {
  failing: ['Stopping more than it should', 'critical', 'alert-circle'],
  inactive: ['Doing nothing', 'warning', 'triangle'],
  limited: ['Doing part of it', 'warning', 'triangle'],
};

interface FeaturesData { view: any; components: any; presets: any }

export const featuresPage: PageDef<FeaturesData> = {
  re: /^\/features$/,
  nav: 'features',
  title: 'Features',
  load: async () => {
    const [view, components, presets] = await Promise.all([api('v1/features'), api('v1/components'), api('v1/feature-presets')]);
    return { view, components, presets };
  },
  View: FeaturesView,
};

function FeaturesView({ data: { view, components, presets } }: { data: FeaturesData }) {
  const features: Feature[] = view.features;
  const monitored = features.filter((f) => f.mode === 'monitor' && f.group === 'controls');
  const failing = features.filter((f) => f.status === 'failing');
  const short = features.filter((f) => f.status === 'inactive' || f.status === 'limited');
  return (
    <div className="page">
      <PageHead
        title="Features"
        sub="Choose which parts of AgentGov you use, and how strictly. In monitor mode a control decides and records what it would have done, but lets the call through: try it on real traffic before you enforce it."
        actions={[<RefreshButton key="refresh" />]}
      />
      {failing.length ? (
        <Callout tone="critical" icon="alert-circle">
          <span>
            <strong>{`${plural(failing.length, 'feature')} stopping more than ${failing.length === 1 ? 'it' : 'they'} should: `}</strong>
            {failing.map((f) => f.title).join(', ')}{'. See why below.'}
          </span>
        </Callout>
      ) : null}
      {short.length ? (
        <Callout tone="warning" icon="triangle">
          <span>
            <strong>{`${plural(short.length, 'feature')} not doing all ${short.length === 1 ? 'its mode says' : 'their modes say'}: `}</strong>
            {short.map((f) => f.title).join(', ')}{". Turn off the ones you don't use; for the others, see below what each needs."}
          </span>
        </Callout>
      ) : null}
      {monitored.length ? (
        <Callout tone="warning" icon="eye">
          <span>
            <strong>{`${plural(monitored.length, 'control')} in monitor mode. `}</strong>
            {'Calls they would have stopped go through, and the ledger records them as warnings. '}
            <a href="#/ledger?decision=monitored">See what they would have stopped</a>.
          </span>
        </Callout>
      ) : null}
      <ComponentsCard view={components} />
      <PresetsCard view={presets} />
      {Object.entries(view.groups as Record<string, string>).map(([group, title]) => {
        const list = features.filter((f) => f.group === group);
        return list.length ? <FeaturesCard key={group} title={title} list={list} /> : null;
      })}
    </div>
  );
}

// What the control plane reaches itself, and what each governance processor says it reaches.
const CHECK_NAMES: Record<string, string> = { opa: 'OPA', keycloak: "Keycloak's keys", presidio: 'Presidio', guardian: 'Granite Guardian', authzen: 'Your decision point' };

function checkChip(name: string, c: any): ReactNode {
  const label = CHECK_NAMES[name] || name;
  if (!c || !c.configured) {
    // A processor with no AGENTGOV_OPA_URL still asks one, at its default address.
    if (c && c.detail) return <PlainChip text={`${label}: ${c.ok ? 'reachable' : 'unreachable'}`} tone={c.ok ? 'good' : 'critical'} iconName={c.ok ? 'check' : 'alert-circle'} title={c.detail} />;
    return <PlainChip text={`${label}: not set up`} title="Not set up where it runs" />;
  }
  return c.ok
    ? <PlainChip text={`${label}: reachable`} tone="good" iconName="check" />
    : <PlainChip text={`${label}: unreachable`} tone="critical" iconName="alert-circle" title={c.detail || null} />;
}

const checkChips = (names: string[], checks: Record<string, any>) => (
  <div className="chip-row">{names.map((n) => <Fragment key={n}>{checkChip(n, checks[n])}</Fragment>)}</div>
);

// What a governance processor does when what it depends on fails (AGENTGOV_*_FAILURE_MODE).
const FAILURE_WORDS: Record<string, [label: string, words: Record<string, string>]> = {
  gateway_failure_mode: ['Calls it can\'t check', { modes: 'refused while a control is enforced', closed: 'refused', open: 'let through, recorded' }],
  presidio_failure_mode: ['Presidio down', { closed: 'refused while data protection is enforced', open: 'personal data not looked for' }],
  guardian_failure_mode: ['Granite Guardian down', { open: 'the rules decide alone', closed: 'refused where it is waited for' }],
  authzen_failure_mode: ['Your decision point down', { closed: 'refused while it is enforced', open: 'AgentGov decides alone' }],
};

function failureLine(settings: Record<string, string> | null | undefined): ReactNode {
  const parts = Object.entries(FAILURE_WORDS)
    .filter(([k]) => settings?.[k])
    .map(([k, [label, words]]) => `${label}: ${words[settings![k]] || settings![k]}`);
  return parts.length ? <div className="cell-sub">{`${parts.join('. ')}.`}</div> : null;
}

// Where destinations' credentials and model providers' keys may go (AGENTGOV_CREDENTIAL_HOSTS).
function credentialHosts(hosts: string[] | null | undefined): ReactNode {
  if (hosts?.length) return <div><PlainChip text="Listed hosts only" tone="good" iconName="lock" /><div className="cell-sub break">{hosts.join(', ')}</div></div>;
  return (
    <div>
      <PlainChip text="Any host" tone="warning" iconName="triangle" />
      <div className="cell-sub">{"An administrator can send destinations' credentials and model providers' keys to any host, by changing a URL. List the hosts they may go to in AGENTGOV_CREDENTIAL_HOSTS."}</div>
    </div>
  );
}

// What vouches for the evidence ledger outside its database: the authority's time-stamps,
// checked against its certificates, and the head kept in a file a restore doesn't touch.
function ledgerChecks(lg: any): ReactNode {
  if (!lg) return null;
  const stamps = lg.time_stamps || {};
  const kept = lg.witness || {};
  return (
    <div>
      <div className="chip-row">
        {stamps.configured
          ? <PlainChip text={stamps.ok ? 'Time-stamps: authority checked' : 'Time-stamps: authority not checked'} tone={stamps.ok ? 'good' : 'warning'} iconName={stamps.ok ? 'check' : 'triangle'} title={stamps.detail || null} />
          : <PlainChip text="Time-stamps: none" title={stamps.detail || null} />}
        {kept.configured
          ? <PlainChip text="Head kept outside the database" tone="good" iconName="check" />
          : <PlainChip text="Head not kept outside the database" tone="warning" iconName="triangle" title={kept.detail || null} />}
      </div>
      {[stamps, kept].filter((c) => !c.ok && c.detail).map((c, n) => <div key={n} className="cell-sub">{c.detail}</div>)}
    </div>
  );
}

function ComponentsCard({ view }: { view: any }) {
  const cp = view.control_plane || {};
  const processors: any[] = view.processors || [];
  const rows: FactRow[] = [
    ['Control plane', checkChips(['opa', 'keycloak'], cp)],
    'credential_hosts' in view ? ['Credentials go to', credentialHosts(view.credential_hosts)] : null,
    view.ledger ? ['Evidence ledger', ledgerChecks(view.ledger)] : null,
    ...processors.map((p): FactRow => [
      <span>{'Governance processor '}<code>{p.instance}</code></span>,
      <div>
        {checkChips(['opa', 'presidio', 'guardian', 'authzen'], p.checks)}
        <div className="cell-sub">{p.fresh ? 'Reported ' : 'Out of touch: last reported '}<TimeEl iso={p.reported_at} /></div>
        {failureLine(p.settings)}
        {Object.entries(p.checks as Record<string, any>).filter(([, c]) => c.configured && !c.ok && c.detail)
          .map(([n, c]) => <div key={n} className="cell-sub">{`${CHECK_NAMES[n] || n}: ${c.detail}`}</div>)}
      </div>,
    ]),
  ];
  return (
    <Card
      title="What AgentGov can reach"
      sub="Checked now by the control plane, and reported every minute by each governance processor where it runs. A feature that needs what isn't reachable says so below."
    >
      <div>
        {processors.length ? null : (
          <Callout tone="warning" icon="triangle">
            {"No governance processor has reported. The controls at the gateway check only calls through AgentGov's gateway, and nothing is known to check them."}
          </Callout>
        )}
        <Facts rows={rows} />
      </div>
    </Card>
  );
}

// Starting points that set many modes at once.
function PresetsCard({ view }: { view: any }) {
  const applied = view.applied ? ` The deployment applied ${view.applied} (AGENTGOV_FEATURE_PRESET).` : '';
  return (
    <Card
      title="Starting points"
      sub={`Set many modes at once, then change them one by one. Each change goes into the ledger with the preset's name; features the deployment pins keep their modes.${applied}`}
    >
      <ul className="apply-results" role="list">
        {(view.presets as Preset[]).map((p) => (
          <li key={p.preset} data-preset={p.preset}>
            <div>
              <span className="cell-title">{p.title}</span>
              <div className="cell-sub">{p.description}</div>
              <div className="cell-sub">{p.changes.length ? `Would change ${plural(p.changes.length, 'feature')} now.` : 'Changes nothing now.'}</div>
            </div>
            {can('admin') && p.changes.length
              ? <button type="button" className="btn" onClick={guarded(() => applyPreset(p))}>{`Apply ${p.title.toLowerCase()}…`}</button>
              : null}
          </li>
        ))}
      </ul>
    </Card>
  );
}

async function applyPreset(p: Preset) {
  const words = (m: string) => (MODE_WORDS[m] || humanize(m)).toLowerCase();
  const weakens = p.changes.some((c: any) => c.to === 'off' || (c.from === 'enforce' && c.to === 'monitor'));
  const result = await ask<any>({
    title: `${p.title}?`,
    text: p.description,
    tone: weakens ? 'danger' : 'primary', iconName: weakens ? 'triangle' : 'info',
    confirm: `Change ${plural(p.changes.length, 'feature')}`, busy: 'Changing…',
    extra: (
      <div className="stack-tight">
        <ul className="apply-results" role="list">
          {p.changes.map((c: any, n: number) => (
            <li key={n}><span>{c.title}</span><span className="cell-sub">{`${words(c.from)} to ${words(c.to)}`}</span></li>
          ))}
        </ul>
        {p.kept.length ? <p className="cell-sub">{'Left as they are: '}{p.kept.map((c: any) => `${c.title} (${c.reason})`).join('; ')}.</p> : null}
      </div>
    ),
    submit: () => api(`v1/feature-presets/${encodeURIComponent(p.preset)}`, { method: 'POST' }),
  });
  if (result?.changes) toast(`${p.title}: ${plural(result.changes.length, 'feature')} changed.`);
  await refresh();
}

function FeaturesCard({ title, list }: { title: string; list: Feature[] }) {
  return (
    <Card title={title} flush>
      <div className="table-wrap">
        <table className="data rtable features-table">
          <caption className="sr-only">{title}</caption>
          <thead><tr>{['Feature', 'Mode', 'Now'].map((t) => <th key={t} scope="col">{t}</th>)}</tr></thead>
          <tbody>
            {list.map((f) => (
              <tr key={f.key} data-feature={f.key}>
                <td data-label="Feature">
                  <span className="cell-title">{f.title}</span>
                  <div className="cell-sub">{f.description}</div>
                  {f.needs ? <div className="cell-sub">{`Needs ${f.needs}.`}</div> : null}
                </td>
                <td data-label="Mode"><ModeControl f={f} />{exceptionsBlock(f)}</td>
                <td data-label="Now">{featureNow(f)}{featureProvenance(f)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

// What the mode does, or, when it can't do all of it, what stops it.
function featureNow(f: Feature): ReactNode {
  const status = FEATURE_STATUS[f.status];
  if (!status || !(f.problems || []).length) return <div>{f.effect}</div>;
  const [words, tone, iconName] = status;
  return (
    <div className="stack-tight">
      <PlainChip text={words} tone={tone} iconName={iconName} />
      {(f.problems || []).map((p: string, n: number) => <div key={n} className="break">{p}</div>)}
      <div className="cell-sub">{`Its mode: ${f.effect}`}</div>
    </div>
  );
}

/** Who set a feature's mode (featureProvenance(f)): the deployment, an administrator, or nobody (the default). */
export function featureProvenance(f: any): ReactNode {
  if (f.set_by === 'deployment') {
    return <div className="cell-sub"><Icon name="lock" />{' Set by the deployment (AGENTGOV_FEATURES)'}</div>;
  }
  if (f.set_by === 'admin') return <div className="cell-sub">{`Set by ${f.changed_by} `}<TimeEl iso={f.changed_at} /></div>;
  return <div className="cell-sub">The default</div>;
}

// A control's exceptions: its mode for the agents in a scope, the first that matches.
function plainScopes(f: Feature): any[] {
  return (f.scopes || []).map(({ describe: _describe, agents: _agents, missing: _missing, ...e }: any) => e);
}

// How many agents an exception applies to now, and what it names that there isn't.
function exceptionReach(e: any): ReactNode {
  if (e.agents === undefined) return null;
  const missing = e.missing?.length ? `There is no ${e.missing.join(', ')}. ` : '';
  const reach = e.agents ? `Applies to ${plural(e.agents, 'agent')} now.` : 'Applies to no agent now.';
  return <span className={`exception-reach cell-sub${missing || !e.agents ? ' tone-text-warning' : ''}`}>{`${missing}${reach}`}</span>;
}

function exceptionsBlock(f: Feature): ReactNode {
  if (!f.scopable) return null;
  const pinned = f.set_by === 'deployment';
  const editable = can('admin') && !pinned;
  const list: any[] = f.scopes || [];
  if (!list.length && !editable) return null;
  return (
    <div className="exceptions">
      {list.length ? (
        <ul className="exception-list" role="list">
          {list.map((e, i) => (
            <li key={i}>
              <PlainChip text={MODE_WORDS[e.mode] || e.mode} tone={e.mode === 'enforce' ? 'good' : e.mode === 'monitor' ? 'warning' : null} />
              <span className="exception-scope">
                {ruleScope(e.scope)}{e.note ? <span className="cell-sub">{` (${e.note})`}</span> : null}{exceptionReach(e)}
              </span>
              {editable ? (
                <button type="button" className="icon-btn" title="Remove this exception"
                  aria-label={`Remove the exception: ${MODE_WORDS[e.mode] || e.mode} for ${ruleScope(e.scope)}`}
                  onClick={guarded(() => removeException(f, i))}>
                  <Icon name="x" />
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
      {pinned && list.length ? <div className="cell-sub">Not applied: the deployment pins this feature for every agent.</div> : null}
      {editable ? <button type="button" className="btn btn--sm btn--ghost" onClick={guarded(() => addException(f))}><Icon name="plus" />Add an exception</button> : null}
    </div>
  );
}

async function addException(f: Feature) {
  const result = await ask<any>({
    title: `${f.title}: an exception`,
    text: 'Its mode for the agents in a scope. Every box you fill in must match; the first exception that matches an agent applies to it, and the others have the feature\'s mode.',
    confirm: 'Add the exception', busy: 'Saving…',
    fields: [
      { id: 'mode', label: 'Mode for these agents', type: 'select', required: true, value: f.mode === 'enforce' ? 'monitor' : 'enforce', options: f.modes.map((m: string) => ({ value: m, label: MODE_WORDS[m] || humanize(m) })) },
      {
        type: 'row', fields: [
          { id: 'blueprints', label: 'Blueprints', mono: true },
          { id: 'teams', label: 'Teams', mono: true },
        ],
      },
      {
        type: 'row', fields: [
          { id: 'platforms', label: 'Platforms', mono: true, hint: 'gateway, microsoft-365, copilot-studio, aws, google-cloud, salesforce, databricks or microsoft-foundry.' },
          { id: 'environments', label: 'Environments', mono: true },
        ],
      },
      { id: 'labels', label: 'With labels', mono: true, hint: 'key=value, separated by commas.' },
      { id: 'note', label: 'Why', hint: 'For whoever reads it next.' },
    ],
    submit: async (v) => {
      const scope: Record<string, any> = {};
      for (const key of ['blueprints', 'teams', 'platforms', 'environments']) {
        const list = parseList(v[key]);
        if (list.length) scope[key] = list;
      }
      const labels = parseLabels(v.labels);
      if (Object.keys(labels).length) scope.labels = labels;
      if (!Object.keys(scope).length) throw new Error('Say which agents: a blueprint, a team, a platform, an environment or a label.');
      const entry: Record<string, any> = { mode: v.mode, scope };
      if (v.note) entry.note = v.note;
      try {
        return await api(`v1/features/${encodeURIComponent(f.key)}`, { method: 'PUT', body: { scopes: [...plainScopes(f), entry] } });
      } catch (err) {
        // What is wrong with this exception, not where it is in the list ("scopes[3].scope").
        if (err instanceof ApiError) err.message = err.message.replace(/\bscopes\[\d+\]\.scope: (\w)/i, (_, c: string) => c.toUpperCase());
        throw err;
      }
    },
  });
  if (result?.scopes) toast(`${f.title}: ${plural(result.scopes.length, 'exception')}.`);
  await refresh();
}

async function removeException(f: Feature, i: number) {
  const e = f.scopes[i];
  const ok = await ask({
    title: 'Remove this exception?',
    text: `${f.title}: ${(MODE_WORDS[e.mode] || e.mode).toLowerCase()} for ${ruleScope(e.scope)}. These agents then have the feature's mode, ${(MODE_WORDS[f.mode] || f.mode).toLowerCase()}, unless a later exception takes them in.`,
    tone: 'danger', iconName: 'triangle', confirm: 'Remove it',
  });
  if (!ok) return;
  try {
    const out = await api(`v1/features/${encodeURIComponent(f.key)}`, { method: 'PUT', body: { scopes: plainScopes(f).filter((_, j) => j !== i) } });
    toast(`${f.title}: ${plural(out.scopes.length, 'exception')} left.`);
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
  await refresh();
}

/**
 * A feature's mode, to choose (modeControl(f)): radios, or its mode where it can't be changed.
 * The mode chosen shows as chosen while it is confirmed and saved; the page then shows the
 * feature's mode again, as it loads it.
 */
export function ModeControl({ f }: { f: any }) {
  const [chosen, setChosen] = useSynced<string>(f.mode, f);
  if (!can('admin') || f.set_by === 'deployment') return <Chip kind="mode" value={f.mode} />;
  const name = `mode-${f.key}`;
  return (
    <div className="segmented" role="radiogroup" aria-label={`${f.title}: mode`}>
      {(f.modes as string[]).map((m) => {
        const id = `${name}-${m}`;
        const unavailable = f.unavailable?.[m];
        const choose = guarded(() => chooseMode(f, m));
        return (
          <label key={m} htmlFor={id} title={unavailable || f.effects[m] || undefined}>
            <input type="radio" id={id} name={name} value={m} checked={m === chosen}
              disabled={Boolean(unavailable) && m !== f.mode}
              onChange={() => {
                setChosen(m);
                void choose();
              }} />
            <span>{MODE_WORDS[m] || humanize(m)}</span>
          </label>
        );
      })}
    </div>
  );
}

async function chooseMode(f: Feature, mode: string) {
  if (f.modes.indexOf(mode) < f.modes.indexOf(f.mode)) {
    const ok = await ask({
      title: `${f.title}: ${(MODE_WORDS[mode] || mode).toLowerCase()}?`,
      text: f.effects[mode],
      tone: 'danger', iconName: 'triangle', confirm: `Set to ${(MODE_WORDS[mode] || mode).toLowerCase()}`,
    });
    if (!ok) {
      await refresh();
      return;
    }
  }
  try {
    const out = await api(`v1/features/${encodeURIComponent(f.key)}`, { method: 'PUT', body: { mode } });
    toast(`${f.title}: ${(MODE_WORDS[out.mode] || out.mode).toLowerCase()}. ${out.effect}`);
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
  await refresh();
}
