// Models: the providers agents call through the gateway, at /llm/<provider>, their budgets,
// who spends, and what was used.

import { useState } from 'react';
import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import {
  AgentLink, agentHref, Callout, Card, Chip, Copyable, EmptyState, PageHead, PlainChip, RefreshButton,
} from '../components/ui';
import { api, getInfo } from '../lib/api';
import { fmt, plural } from '../lib/format';
import { orNull } from '../lib/forms';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { featureModes, NAME_HINT } from '../lib/shared';
import { TONE_COLOR } from '../lib/status';

type Provider = any;
type Usage = any;

const PROVIDER_KINDS = [
  ['openai', 'OpenAI'], ['anthropic', 'Anthropic'], ['gemini', 'Google Gemini'],
  ['openai-compatible', 'OpenAI-compatible server (vLLM, Ollama, LiteLLM, hosted APIs)'],
];

interface ModelsData {
  providers: Provider[];
  usage: Usage;
  info: any;
  features: Record<string, string>;
}

export const modelsPage: PageDef<ModelsData> = {
  re: /^\/models$/,
  nav: 'models',
  title: 'Models',
  load: async () => {
    const [providers, usage, info, features] = await Promise.all([
      api('v1/models/providers'), api('v1/models/usage?days=7'), getInfo(), featureModes().catch(() => ({} as Record<string, string>)),
    ]);
    return { providers, usage, info, features };
  },
  View: ({ data: { providers, usage, info, features } }) => {
    const gateway = (info?.gateway_url || '').replace(/\/$/, '');
    return (
      <div className="page">
        <PageHead
          title="Models"
          sub="Model providers agents call through the gateway, at /llm/<provider>, with their AgentGov token instead of the provider's API key. Every prompt and answer is checked, and every call is metered."
          actions={[
            can('admin') ? (
              <button key="add" type="button" className="btn btn--primary" onClick={guarded(() => providerForm(null))}>
                <Icon name="plus" />Add provider
              </button>
            ) : null,
            <RefreshButton key="refresh" />,
          ]}
        />
        {features['model-gateway'] === 'off' ? (
          <Callout tone="warning" icon="power">
            <span><strong>The model gateway is off: </strong>{'no provider is published on the gateway. '}<a href="#/features">Features</a>{'.'}</span>
          </Callout>
        ) : null}
        <ProvidersCard providers={providers} gateway={gateway} />
        <BudgetsCard usage={usage} />
        <SpendCard usage={usage} />
        <UsageCard usage={usage} />
      </div>
    );
  },
};

function ProvidersCard({ providers, gateway }: { providers: Provider[]; gateway: string }) {
  const body = providers.length ? (
    <div className="table-wrap">
      <table className="data rtable">
        <caption className="sr-only">Model providers</caption>
        <thead>
          <tr>
            {['Provider', 'Status', 'Agents call', 'Prices (USD per 1M tokens)', ''].map((t, i) => (
              <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {providers.map((p) => (
            <tr key={p.name} data-provider={p.name}>
              <td data-label="Provider">
                <span className="cell-title">{p.name}</span>
                <div className="cell-sub">{(PROVIDER_KINDS.find(([k]) => k === p.kind) || [p.kind, p.kind])[1]}{p.base_url ? ` at ${p.base_url}` : ''}</div>
                <div className="cell-sub">{`Key file: ${p.key_file}`}</div>
              </td>
              <td data-label="Status">
                <Chip kind="server" value={p.status} />
                <div className="cell-sub">{p.trust_level === 'verified' ? 'Verified: may receive personal data' : 'Unverified: personal data is masked'}</div>
              </td>
              <td data-label="Agents call"><Copyable text={`${gateway}${p.route}/v1/chat/completions`} label={`${p.name} endpoint`} /></td>
              <td data-label="Prices">
                {Object.keys(p.prices || {}).length ? (
                  <div className="chip-row">
                    {Object.entries(p.prices).map(([m, price]: [string, any]) => <PlainChip key={m} text={`${m}: ${price.input} in, ${price.output} out`} mono />)}
                  </div>
                ) : <span className="muted">None: cost is not counted</span>}
              </td>
              <td data-label="">
                {can('contain') ? (
                  <div className="btn-row">
                    {can('admin') ? <button type="button" className="btn btn--sm" onClick={guarded(() => providerForm(p))}><Icon name="edit" />Edit</button> : null}
                    <button type="button" className="btn btn--sm" onClick={guarded(() => blockProvider(p))}>
                      <Icon name={p.status === 'blocked' ? 'undo' : 'ban'} />{p.status === 'blocked' ? 'Unblock' : 'Block'}
                    </button>
                    {can('admin') ? <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => deleteProvider(p))}><Icon name="trash" />Delete</button> : null}
                  </div>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : <EmptyState title="No model providers" text="Add one, then put its API key where the gateway reads it. Agents call it with their own token and never see the key." />;
  return <Card title="Providers" flush={Boolean(providers.length)}>{body}</Card>;
}

function BudgetsCard({ usage }: { usage: Usage }) {
  const rows: any[] = (usage.today || []).filter((b: any) => b.daily_token_budget != null);
  if (!rows.length) return null;
  return (
    <Card title="Budgets today" sub={`Tokens each agent used on ${usage.day} (UTC), against its daily budget`}>
      <ul className="risk-list" role="list">
        {rows.map((b, i) => {
          const tone = b.over_budget ? 'critical' : 'accent';
          return (
            <li key={i}>
              <a href={agentHref(b.agent_id)} className="cell-title break">{b.agent_name}</a>
              <span className="small">
                {`${fmt(b.used_today)} of ${fmt(b.daily_token_budget)} tokens`}
                {b.over_budget ? <>{' '}<PlainChip text="Over budget" tone="critical" iconName="ban" title="Its model calls are refused until the day ends (UTC)" /></> : null}
              </span>
              <div className="meter" role="img" aria-label={`${fmt(b.used_today)} of ${fmt(b.daily_token_budget)} tokens`} style={{ background: 'var(--neutral-tint)' }}>
                <span style={{ width: `${b.daily_token_budget ? Math.min(100, (b.used_today / b.daily_token_budget) * 100) : 100}%`, background: TONE_COLOR[tone] }} />
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

// Usage added up per owner or per sponsor of the agents behind it.
function SpendCard({ usage }: { usage: Usage }) {
  const [by, setBy] = useState<'owner' | 'sponsor'>('owner');
  const groups: Record<string, any[]> = { owner: usage.by_owner || [], sponsor: usage.by_sponsor || [] };
  if (!groups.owner.length) return null;
  const words = { owner: ['Owner', 'No owner'], sponsor: ['Sponsor', 'No sponsor'] };
  const choose = (
    <div className="segmented" role="radiogroup" aria-label="Add up per">
      {(['owner', 'sponsor'] as const).map((x) => (
        <label key={x} htmlFor={`spend-${x}`}>
          <input type="radio" id={`spend-${x}`} name="spend-by" value={x} checked={by === x} onChange={() => setBy(x)} />
          <span>{words[x][0]}</span>
        </label>
      ))}
    </div>
  );
  return (
    <Card
      title="Who is spending"
      sub="The last 7 days, per owner and per sponsor of the agents. An agent with several sponsors counts in full for each."
      actions={choose}
      flush
    >
      <div>
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">{`Model usage per ${by}`}</caption>
            <thead>
              <tr>{[words[by][0], 'Agents', 'Calls', 'Tokens', 'Cost'].map((c, i) => <th key={i} scope="col" className={i ? 'num' : undefined}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {groups[by].map((g, i) => (
                <tr key={i}>
                  <td data-label={words[by][0]}>{g[by] ? <span className="break">{g[by]}</span> : <span className="muted">{words[by][1]}</span>}</td>
                  <td data-label="Agents" className="num">{fmt(g.agents)}</td>
                  <td data-label="Calls" className="num">{fmt(g.calls)}</td>
                  <td data-label="Tokens" className="num">{fmt(g.input_tokens + g.output_tokens)}</td>
                  <td data-label="Cost" className="num">{g.cost_usd ? `$${g.cost_usd.toFixed(4)}` : <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  );
}

function UsageCard({ usage }: { usage: Usage }) {
  const t = usage.totals || {};
  const rows: any[] = usage.rows || [];
  const numeric = ['Calls', 'Tokens in', 'Tokens out', 'Cost'];
  return (
    <Card
      title="Usage, last 7 days"
      sub={rows.length ? `${plural(t.calls, 'call')}, ${fmt(t.refused)} refused · ${fmt(t.input_tokens)} tokens in, ${fmt(t.output_tokens)} out${t.cost_usd ? ` · $${t.cost_usd.toFixed(2)}` : ''}` : null}
      flush={Boolean(rows.length)}
    >
      {rows.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">Model usage</caption>
            <thead>
              <tr>{['Day', 'Agent', 'Model', 'Calls', 'Tokens in', 'Tokens out', 'Cost'].map((c) => <th key={c} scope="col" className={numeric.includes(c) ? 'num' : undefined}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  <td data-label="Day">{r.day}</td>
                  <td data-label="Agent">
                    {r.agent_id ? <AgentLink id={r.agent_id} name={r.agent_name} /> : <span className="muted" title="Calls without an agent token (unknown callers in monitor mode)">Unidentified</span>}
                  </td>
                  <td data-label="Model"><code>{`${r.provider}/${r.model || '?'}`}</code></td>
                  <td data-label="Calls" className="num">{fmt(r.calls)}{r.refused ? <div className="cell-sub">{`${fmt(r.refused)} refused`}</div> : null}</td>
                  <td data-label="Tokens in" className="num">{fmt(r.input_tokens)}</td>
                  <td data-label="Tokens out" className="num">{fmt(r.output_tokens)}</td>
                  <td data-label="Cost" className="num">{r.cost_usd ? `$${r.cost_usd.toFixed(4)}` : <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <EmptyState title="No model calls yet" text="Calls through the gateway show up here once the OpenTelemetry Collector forwards the gateway's access logs." />}
    </Card>
  );
}

function parsePrices(text: string): Record<string, { input: number; output: number }> {
  const out: Record<string, { input: number; output: number }> = {};
  for (const line of String(text || '').split('\n').map((l) => l.trim()).filter(Boolean)) {
    const m = line.match(/^(.+?)\s*[:=]\s*([\d.]+)\s*,\s*([\d.]+)$/);
    if (!m) throw new Error(`Write each price as "model: input, output" in USD per million tokens ("${line}").`);
    out[m[1].trim()] = { input: Number(m[2]), output: Number(m[3]) };
  }
  return out;
}

function formatPrices(prices: Record<string, { input: number; output: number }> | null | undefined): string {
  return Object.entries(prices || {}).map(([m, p]) => `${m}: ${p.input}, ${p.output}`).join('\n');
}

async function providerForm(p: Provider | null) {
  const editing = Boolean(p);
  const saved = await ask<Provider>({
    title: editing ? `Edit ${p.name}` : 'Add a model provider',
    text: "The gateway reads the provider's API key from a file mounted into it; the key never enters AgentGov. Changes are recorded in the evidence ledger.",
    iconName: editing ? 'edit' : 'models', confirm: editing ? 'Save changes' : 'Add provider', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'openai', hint: `${NAME_HINT} Agents call it at /llm/<name>.` },
      { id: 'kind', label: 'Kind', type: 'select', value: p?.kind || 'openai', options: PROVIDER_KINDS.map(([value, label]) => ({ value, label })) },
      { id: 'base_url', label: 'Base URL', mono: true, value: p?.base_url || '', placeholder: 'http://vllm:8000/v1', hint: 'Only for an OpenAI-compatible server: its OpenAI API base, as an OpenAI SDK takes it.' },
      { id: 'key_file', label: 'Key file', mono: true, value: p && p.key_file !== `/model-keys/${p.name}` ? p.key_file : '', placeholder: '/model-keys/<name>', hint: 'Where the gateway reads the API key. Empty: /model-keys/<name>.' },
      {
        id: 'trust_level', label: 'Trust', type: 'select', value: p?.trust_level || 'unverified', options: [
          { value: 'unverified', label: 'Unverified: personal data in prompts is masked' },
          { value: 'verified', label: 'Verified (a data processing agreement covers it): personal data may be sent' },
        ],
      },
      { id: 'prices', label: 'Prices', type: 'code', rows: 2, value: formatPrices(p?.prices), placeholder: 'gpt-4o*: 2.5, 10', hint: 'One model pattern per line: USD per million input tokens, then output tokens.' },
      { id: 'description', label: 'Description', type: 'textarea', value: p?.description || '' },
    ],
    submit: (v) => {
      const body = {
        kind: v.kind, base_url: v.kind === 'openai-compatible' ? orNull(v.base_url) : null, key_file: orNull(v.key_file),
        trust_level: v.trust_level, prices: parsePrices(v.prices), description: v.description,
      };
      if (editing) return api(`v1/models/providers/${encodeURIComponent(p.name)}`, { method: 'PATCH', body, ifMatch: p.version });
      return api('v1/models/providers', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}. Agents call it at ${saved.route} once the gateway has its key.`);
  await refresh();
}

async function blockProvider(p: Provider) {
  const block = p.status !== 'blocked';
  const done = await ask({
    title: block ? `Block ${p.name}?` : `Unblock ${p.name}?`,
    text: block ? 'Every model call to it is refused within a second, for every agent.' : 'Agents with access may call it again.',
    tone: block ? 'danger' : 'primary', iconName: block ? 'ban' : 'undo', confirm: block ? 'Block' : 'Unblock',
    submit: () => api(`v1/models/providers/${encodeURIComponent(p.name)}/${block ? 'block' : 'unblock'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(block ? `Blocked ${p.name}.` : `Unblocked ${p.name}.`);
  await refresh();
}

async function deleteProvider(p: Provider) {
  const done = await ask({
    title: `Delete ${p.name}?`,
    text: 'Its route goes from the gateway. Its usage history stays.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete provider', busy: 'Deleting…',
    submit: () => api(`v1/models/providers/${encodeURIComponent(p.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${p.name}.`);
  await refresh();
}
