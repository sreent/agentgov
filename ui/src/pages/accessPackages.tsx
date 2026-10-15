// Access packages on agents: asking for them, deciding, renewing and revoking; the Entra
// access packages an agent's identity holds; an organisation policy's card, and trying a call
// against the policies (what if).

import { useEffect, useRef, type ChangeEvent, type FormEvent, type ReactNode } from 'react';
import { ask } from '../components/dialog';
import { useSynced } from '../components/hooks';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, Chip, EmptyState, Facts, JsonBlock, PlainChip, TimeEl } from '../components/ui';
import { api } from '../lib/api';
import { fmt, humanize, plural } from '../lib/format';
import { parseList } from '../lib/forms';
import { refresh } from '../lib/router';
import { can, getMe } from '../lib/session';
import { deletePolicy, policyFormFlow, togglePolicy } from './policies';

/** Ask for a package for an agent; asked again while it holds one (`current`), it is a
 * renewal. Resolves to what was done, or null. */
export async function requestPackage(agent: any, packages: any[], current: any): Promise<any> {
  const choices = current ? [current] : packages;
  if (!choices.length) {
    toast('There are no access packages yet: an admin creates them on the Policies page.', { tone: 'warning' });
    return null;
  }
  const first = choices[0];
  const done = await ask<any>({
    title: current ? `Renew ${current.name} for ${agent.name}?` : `Request access for ${agent.name}`,
    text: current
      ? 'It carries on from now for the days you ask, and never ends sooner than it would have. An approver decides, unless the package needs no approval.'
      : 'An approver decides, unless the package needs no approval. The agent holds what it grants until it expires.',
    iconName: 'key', confirm: current ? 'Ask to renew' : 'Request access',
    fields: [
      current ? null : { id: 'package', label: 'Access package', type: 'select', value: first.name, options: choices.map((pk) => ({ value: pk.name, label: `${pk.name} (up to ${plural(pk.duration_days, 'day')})` })) },
      { id: 'days', label: 'For how many days', type: 'number', min: 1, value: first.duration_days, required: true },
      { id: 'reason', label: 'Why the agent needs it', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown to the approver.' },
    ],
    submit: (v) => api('v1/access-assignments', {
      method: 'POST', body: { agent: agent.id || agent.agent_id, package: current ? current.name : v.package, days: Number(v.days), reason: v.reason },
    }),
  });
  if (!done) return null;
  toast(done.status === 'active' ? `${done.package} is granted to ${done.agent_name} until ${done.expires_at.slice(0, 10)}.` : `Asked for ${done.package} for ${done.agent_name}: an approver decides.`);
  return done;
}

/** Approve, deny or revoke an assignment, after asking; resolves to what was done, or null. */
export async function assignmentAction(row: any, action: 'approve' | 'deny' | 'revoke'): Promise<any> {
  const words = ({ approve: ['Approve', 'primary', 'check'], deny: ['Deny', 'danger', 'ban'], revoke: ['Revoke', 'danger', 'ban'] } as const)[action];
  const done = await ask<any>({
    title: `${words[0]} ${row.package} for ${row.agent_name}?`,
    text: action === 'revoke'
      ? 'The agent loses what it grants as soon as OPA loads the updated policy bundle.'
      : `Asked by ${row.requested_by} for ${plural(row.days, 'day')}: ${row.reason}`,
    tone: words[1], iconName: words[2], confirm: words[0],
    fields: [{ id: 'note', label: action === 'revoke' ? 'Reason' : 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
    submit: (v) => api(`v1/access-assignments/${encodeURIComponent(row.id)}/${action}`, {
      method: 'POST', body: action === 'revoke' ? { reason: v.note || null } : { note: v.note || null },
    }),
  });
  if (!done) return null;
  toast(`${{ approve: 'Approved', deny: 'Denied', revoke: 'Revoked' }[action]}: ${row.package} for ${row.agent_name}.`);
  return done;
}

/** Keep or remove an assignment at its review; resolves to what was done, or null. */
export async function reviewAssignment(row: any, keep: boolean): Promise<any> {
  const done = await ask<any>({
    title: keep ? `Keep ${row.package} for ${row.agent_name}?` : `Remove ${row.package} from ${row.agent_name}?`,
    text: keep ? 'The agent still needs it: it holds it until it expires, and is asked again at its next review.' : 'The agent loses what it grants as soon as OPA loads the updated policy bundle.',
    tone: keep ? 'primary' : 'danger', iconName: keep ? 'check' : 'ban', confirm: keep ? 'Keep it' : 'Remove it',
    fields: [{ id: 'note', label: 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
    submit: (v) => api(`v1/access-assignments/${encodeURIComponent(row.id)}/review`, { method: 'POST', body: { keep, note: v.note || null } }),
  });
  if (done) toast(keep ? `Kept ${row.package} for ${row.agent_name}.` : `Removed ${row.package} from ${row.agent_name}.`);
  return done;
}

/** What can be done to an assignment, as buttons. */
export function assignmentButtons(row: any, packages: any[], agent: any): ReactNode[] {
  const buttons: ReactNode[] = [];
  const decider = can('approve', agent);
  const actor = getMe()?.actor;
  if (row.status === 'requested' && decider && row.requested_by === actor) {
    buttons.push(<span key="asked" className="muted small">You asked for it: another approver decides.</span>);
  }
  if (row.status === 'requested' && decider && row.requested_by !== actor) {
    buttons.push(
      <button key="approve" type="button" className="btn btn--sm btn--primary" onClick={guarded(async () => { if (await assignmentAction(row, 'approve')) await refresh(); })}><Icon name="check" />Approve</button>,
      <button key="deny" type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(async () => { if (await assignmentAction(row, 'deny')) await refresh(); })}><Icon name="ban" />Deny</button>,
    );
  }
  if (['active', 'expired'].includes(row.status)) {
    const pk = packages.find((x) => x.name === row.package);
    if (pk && decider) {
      buttons.push(<button key="renew" type="button" className="btn btn--sm" onClick={guarded(async () => { if (await requestPackage(agent, packages, pk)) await refresh(); })}><Icon name="refresh" />Renew</button>);
    }
    if (decider || can('contain', agent)) {
      buttons.push(<button key="revoke" type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(async () => { if (await assignmentAction(row, 'revoke')) await refresh(); })}><Icon name="ban" />Revoke</button>);
    }
  }
  return buttons;
}

/** Its Microsoft Entra access packages (entraAccessCard(agent, view)). */
export function EntraAccessCard({ agent, view }: { agent: any; view: any }) {
  const manage = view.mode === 'manage' && can('admin');
  const rows: any[] = view.held || [];
  const remove = (row: any) => guarded(async () => {
    const done = await ask({
      title: `Remove ${row.package} from ${agent.name} in Entra?`,
      text: "AgentGov asks Microsoft Entra to remove the assignment, as its app. Entra removes what it grants the agent's identity, or refuses; the next sync shows which.",
      tone: 'danger', iconName: 'ban', confirm: 'Ask Entra to remove it',
      submit: () => api(`v1/agents/${encodeURIComponent(agent.id)}/entra-access-packages/${encodeURIComponent(row.id)}`, { method: 'DELETE' }),
    });
    if (done) { toast(`Asked Entra to remove ${row.package} from ${agent.name}.`); await refresh(); }
  });
  const assign = guarded(async () => {
    const done = await ask({
      title: `Assign an Entra access package to ${agent.name}`,
      text: "AgentGov asks Microsoft Entra to assign it to the agent's Entra identity, as its app, through the package's policy for agents. The next sync shows it delivered.",
      iconName: 'key', confirm: 'Ask Entra to assign it',
      fields: [{ id: 'package', label: 'Access package', type: 'select', value: view.packages[0]?.id, options: view.packages.map((p: any) => ({ value: p.id, label: p.name })) }],
      submit: (v) => api(`v1/agents/${encodeURIComponent(agent.id)}/entra-access-packages/assign`, { method: 'POST', body: { package: v.package } }),
    });
    if (done) { toast(`Asked Entra to assign it to ${agent.name}.`); await refresh(); }
  });
  let body: ReactNode;
  if (view.mode === 'off') body = <EmptyState title="Turned off" text={<span>Turn on Microsoft Entra access packages on the <a href="#/features">Features</a> page.</span>} />;
  else if (!view.synced_at) body = <EmptyState title="Not read yet" text={<span>The connection runs on a schedule, once AgentGov&apos;s app can read them (<a href="#/platforms">Platforms</a>).</span>} />;
  else if (!rows.length) body = <EmptyState title="None" text="Its Entra identity holds no access package." />;
  else {
    body = (
      <ul className="access-list" role="list">
        {rows.map((row, i) => (
          <li key={row.id ?? i} className="access-row">
            <div className="access-main">
              <div className="cell-title">{row.package}{' '}<Chip kind="entra_access" value={row.state} /></div>
              <div className="cell-sub">{row.expires_at ? <>Expires <TimeEl iso={row.expires_at} /></> : 'No end date'}</div>
            </div>
            {manage ? (
              <div className="btn-row">
                <button type="button" className="btn btn--sm btn--danger-quiet" onClick={remove(row)}><Icon name="ban" />Remove in Entra</button>
              </div>
            ) : null}
          </li>
        ))}
      </ul>
    );
  }
  return (
    <Card
      title="Entra access packages"
      sub={view.mode === 'manage' ? 'What Microsoft Entra ID Governance assigns its Entra identity. Administrators assign and remove them here.' : 'What Microsoft Entra ID Governance assigns its Entra identity, read by AgentGov.'}
      actions={manage && view.packages.length ? [<button key="assign" type="button" className="btn btn--sm" onClick={assign}><Icon name="plus" />Assign</button>] : null}
    >
      {body}
    </Card>
  );
}

/** An agent's access packages (agentAccessCard(agent, rows, packages, mode)). */
export function AgentAccessCard({ agent, rows, packages, mode }: { agent: any; rows: any; packages: any[]; mode: string | undefined }) {
  if (rows instanceof Error) return null;
  const current: any[] = rows.filter((r: any) => ['requested', 'active', 'expired'].includes(r.status));
  const earlier: any[] = rows.filter((r: any) => !current.includes(r));
  const line = (r: any) => (
    <li key={r.id} className="access-row">
      <div className="access-main">
        <div className="cell-title">{r.package}{' '}<Chip kind="access" value={r.status} /></div>
        <div className="cell-sub break">
          {r.status === 'requested' ? `Asked by ${r.requested_by} for ${plural(r.days, 'day')}: ${r.reason}`
            : r.expires_at ? (
              <>
                {r.status === 'expired' ? 'Expired ' : ['active'].includes(r.status) ? 'Expires ' : 'Ended '}
                <TimeEl iso={r.status === 'active' || r.status === 'expired' ? r.expires_at : r.ended_at || r.decided_at} />
              </>
            ) : `${humanize(r.status)} by ${r.decided_by || 'unknown'}`}
        </div>
      </div>
      <div className="btn-row">{assignmentButtons(r, packages, agent)}</div>
    </li>
  );
  const expiredNote = current.some((r) => r.status === 'expired') && mode !== 'enforce' ? (
    <Callout tone="warning" icon="triangle">
      <span>
        <strong>Expired, still used: </strong>
        {mode === 'off' ? 'access packages are off, so they grant nothing.' : 'expired packages are monitored, so the agent keeps the access. Renew or revoke them.'}
      </span>
    </Callout>
  ) : null;
  return (
    <Card
      title="Access packages"
      sub="Extra tools, models and agents it holds for a while once approved."
      actions={can('approve', agent) && packages.length ? [
        <button key="request" type="button" className="btn btn--sm" onClick={guarded(async () => { if (await requestPackage(agent, packages, null)) await refresh(); })}><Icon name="plus" />Request access</button>,
      ] : null}
    >
      {expiredNote}
      {current.length ? <ul className="access-list" role="list">{current.map(line)}</ul>
        : <EmptyState title="No access packages" text={packages.length ? 'Request one when the agent needs more for a while.' : null} />}
      {earlier.length ? (
        <details className="disclosure">
          <summary><Icon name="chevron" />{`Earlier (${fmt(earlier.length)})`}</summary>
          <ul className="access-list" role="list">{earlier.map(line)}</ul>
        </details>
      ) : null}
    </Card>
  );
}

/** An organisation policy (policyCard(p)). */
export function PolicyCard({ p }: { p: any }) {
  return (
    <Card
      title={p.name} level="h3"
      sub={p.description}
      actions={[
        <PlainChip key="enabled" text={p.enabled ? 'Enabled' : 'Disabled'} tone={p.enabled ? 'good' : null} iconName={p.enabled ? 'check-circle' : 'minus'} />,
        <PlainChip key="version" text={`v${p.version}`} mono />,
      ]}
      foot={can('admin') ? (
        <div className="btn-row">
          <button type="button" className="btn btn--sm" onClick={guarded(() => policyFormFlow(p))}><Icon name="edit" />Edit</button>
          <button type="button" className="btn btn--sm" onClick={() => togglePolicy(p)}><Icon name={p.enabled ? 'minus' : 'check'} />{p.enabled ? 'Disable' : 'Enable'}</button>
          <button type="button" className="btn btn--sm btn--danger-quiet" onClick={() => deletePolicy(p)}><Icon name="trash" />Delete</button>
        </div>
      ) : null}
    >
      <Facts rows={[['Package', <code>{p.package}</code>], ['Updated', <TimeEl iso={p.updated_at} />]]} />
      <details className="disclosure">
        <summary><Icon name="chevron" />View Rego source</summary>
        <pre className="kv-pre rego" tabIndex={0}>{p.rego}</pre>
      </details>
    </Card>
  );
}

type CallKind = 'tool' | 'model' | 'agent';

// What the what-if form holds.
interface WhatIfForm {
  kind: CallKind;
  agentId: string;
  user: string;
  groups: string;
  server: string;
  tool: string;
  provider: string;
  model: string;
  target: string;
  phase: 'request' | 'response';
  pii: boolean;
  secret: boolean;
  injection: boolean;
  jailbreak: boolean;
  toolCalls: boolean;
}

// What the what-if card shows below its form.
type WhatIfShown =
  | { state: 'none' }
  | { state: 'empty' }
  | { state: 'missing'; what: string }
  | { state: 'error'; message: string }
  | { state: 'result'; res: any; input: any; example: boolean };

// The scenario the form starts with: a tool call by the agent seen last (an active one with a
// blueprint, if any) to an approved tool server's destructive tool; for a model call, an
// approved provider and a model the agent may call there; for a call to an agent, the first
// that serves A2A.
function whatIfStart(agents: any[], servers: any[], providers: any[]): WhatIfForm {
  const registered = agents.filter((a) => a.status !== 'discovered');
  const discovered = agents.filter((a) => a.status === 'discovered');
  const recent = (a: any) => (a.last_seen_at ? Date.parse(a.last_seen_at) : 0);
  const preferred = registered.filter((a) => a.status === 'active' && a.blueprint).sort((x, y) => recent(y) - recent(x))[0]
    || registered[0] || discovered[0];
  const agentId: string = preferred ? preferred.id : '__unregistered';
  const firstServer = servers.find((ts) => ts.status === 'approved') || servers[0];
  const server: string = firstServer?.name || '';
  const ts0 = servers.find((x) => x.name === server.trim());
  const destructive = (ts0?.tools || []).find((t: any) => t.annotations?.destructiveHint && !t.poisoned);
  const provider: string = (providers.find((p) => p.status === 'approved') || providers[0])?.name || '';
  const serving = agents.filter((a) => a.a2a_url && a.status !== 'deleted');
  return {
    kind: 'tool',
    agentId,
    user: '',
    groups: '',
    server,
    tool: destructive?.name || ts0?.tools?.[0]?.name || '',
    provider,
    model: grantedModels(agents, agentId, provider)[0] || '',
    target: serving[0]?.name || '',
    phase: 'request',
    pii: false,
    secret: false,
    injection: false,
    jailbreak: false,
    toolCalls: false,
  };
}

// The models the chosen agent may call there, where they are names rather than globs.
function grantedModels(agents: any[], agentId: string, provider: string): string[] {
  const agent = agents.find((a) => a.id === agentId);
  return (agent?.effective_model_access || [])
    .filter((g: any) => g.provider === provider.trim())
    .flatMap((g: any) => g.models).filter((m: string) => !/[*?[]/.test(m));
}

/** Try a call against the policies (whatIfCard(agents, servers, providers)). */
export function WhatIfCard({ agents, servers, providers = [] }: { agents: any[]; servers: any[]; providers?: any[] }) {
  // The form starts from the page's data, and starts again from it after refresh(): the
  // card is drawn anew, as the page.
  const [form, setForm] = useSynced(whatIfStart(agents, servers, providers), agents);
  const [shown, setShown] = useSynced<WhatIfShown>(agents.length || servers.length ? { state: 'none' } : { state: 'empty' }, agents);
  const [busy, setBusy] = useSynced(false, agents);
  // The data the scenario was last evaluated for, and the evaluation asked for last.
  const loaded = useRef<unknown>(null);
  const latest = useRef(0);
  const { kind, agentId, user, groups, server, tool, provider, model, target, phase } = form;
  const set = (changes: Partial<WhatIfForm>) => setForm((f) => ({ ...f, ...changes }));

  const registered = agents.filter((a) => a.status !== 'discovered');
  const discovered = agents.filter((a) => a.status === 'discovered');
  const serving = agents.filter((a) => a.a2a_url && a.status !== 'deleted');
  const tools: any[] = servers.find((x) => x.name === server.trim())?.tools || [];
  const models = grantedModels(agents, agentId, provider);
  const isModel = kind === 'model';
  const isAgent = kind === 'agent';
  const text = (key: 'user' | 'groups' | 'server' | 'tool' | 'provider' | 'model' | 'target') => ({
    autoComplete: 'off',
    spellCheck: false,
    value: form[key],
    onChange: (e: ChangeEvent<HTMLInputElement>) => set({ [key]: e.target.value }),
  });
  const check = (key: 'pii' | 'secret' | 'injection' | 'jailbreak' | 'toolCalls') => ({
    checked: form[key],
    onChange: (e: ChangeEvent<HTMLInputElement>) => set({ [key]: e.target.checked }),
  });

  function buildInput(): { path: string; input: any } {
    const agent = agents.find((a) => a.id === agentId);
    const categories = [form.pii ? 'pii' : null, form.secret ? 'secret' : null].filter(Boolean);
    const caller = agentId === '__unregistered'
      ? { client_id: 'agent-not-registered' }
      : { agent_id: agent?.id, client_id: agent?.identity?.client_id || undefined };
    const detections = { categories, prompt_injection: form.injection, injection_score: form.injection ? 0.95 : 0 };
    const name = user.trim();
    const who = name ? { user: { id: name, username: name, groups: parseList(groups), roles: [], via: 'exchange' } } : {};
    if (kind === 'agent') {
      return {
        path: 'agentgov/a2a/decision',
        input: {
          kind: 'a2a', method: 'SendMessage', agent: caller, ...who, target: target.trim(),
          // The person heads the chain of a call made for them.
          chain: name ? [{ type: 'person', id: name, name }] : [], detections: { categories },
        },
      };
    }
    if (kind === 'model') {
      return {
        path: 'agentgov/models/decision',
        input: {
          kind: 'model', phase, agent: caller, ...who, provider: provider.trim(), model: model.trim(),
          detections: { ...detections, jailbreak: form.jailbreak }, tool_calls: form.toolCalls,
        },
      };
    }
    return {
      path: 'agentgov/mcp/decision',
      input: { phase, method: 'tools/call', agent: caller, ...who, resource: { server: server.trim(), name: tool.trim() }, detections },
    };
  }

  async function evaluate(example: boolean) {
    // Only the evaluation asked for last shows (one asked for before a refresh() may answer after).
    const mine = ++latest.current;
    const { path, input } = buildInput();
    const missing = {
      agent: () => !input.target,
      model: () => !input.provider || !input.model,
      tool: () => !input.resource.server || !input.resource.name,
    }[kind]();
    if (missing) {
      const what = { agent: 'the agent it calls', model: 'a model provider and a model', tool: 'a tool server and a tool' }[kind];
      setShown({ state: 'missing', what });
      return;
    }
    setBusy(true);
    try {
      const res = await api('v1/policies/evaluate', { method: 'POST', body: { path, input } });
      if (mine === latest.current) setShown({ state: 'result', res, input, example });
    } catch (err: any) {
      if (mine === latest.current) setShown({ state: 'error', message: err.message });
    } finally {
      if (mine === latest.current) setBusy(false);
    }
  }

  // The scenario filled in is evaluated, as an example, each time the page is drawn: when it
  // loads, and when refresh() loads its data again.
  const evaluateNow = useRef(evaluate);
  evaluateNow.current = evaluate;
  useEffect(() => {
    if (loaded.current === agents) return;
    loaded.current = agents;
    if (agents.length || servers.length) void evaluateNow.current(true);
  }, [agents, servers.length]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void evaluate(false);
  };

  let result: ReactNode = null;
  if (shown.state === 'empty') result = <p className="muted small">Register an agent and a tool server to try a scenario.</p>;
  else if (shown.state === 'missing') result = <Callout tone="warning" icon="alert-circle">{`Choose ${shown.what} to evaluate.`}</Callout>;
  else if (shown.state === 'error') result = <Callout tone="critical" icon="alert-circle"><span><strong>Couldn&apos;t evaluate. </strong>{shown.message}</span></Callout>;
  else if (shown.state === 'result') result = <WhatIfResult res={shown.res} input={shown.input} example={shown.example} />;

  return (
    <section className="card whatif" aria-labelledby="whatif-title">
      <div className="card-head">
        <div className="card-head-text">
          <h2 id="whatif-title">What if</h2>
          <p className="card-sub">Ask the live OPA what it would decide for a tool call, a model call or a call to another agent. Nothing is recorded.</p>
        </div>
      </div>
      <div className="card-body">
        <form className="whatif-form" noValidate onSubmit={onSubmit}>
          <fieldset className="field">
            <legend className="field-label">Call</legend>
            <div className="radio-row">
              <label className="check" htmlFor="wi-kind-tool">
                <input type="radio" name="wi-kind" id="wi-kind-tool" value="tool" checked={kind === 'tool'} onChange={() => set({ kind: 'tool' })} />A tool call
              </label>
              <label className="check" htmlFor="wi-kind-model">
                <input type="radio" name="wi-kind" id="wi-kind-model" value="model" checked={kind === 'model'} onChange={() => set({ kind: 'model' })} />A model call
              </label>
              <label className="check" htmlFor="wi-kind-agent">
                <input type="radio" name="wi-kind" id="wi-kind-agent" value="agent" checked={kind === 'agent'} onChange={() => set({ kind: 'agent' })} />A call to another agent
              </label>
            </div>
          </fieldset>
          <div className="field">
            <label htmlFor="wi-agent">Agent</label>
            <select id="wi-agent" name="agent" value={agentId} onChange={(e) => set({ agentId: e.target.value })}>
              {registered.length ? (
                <optgroup label="Registered">
                  {registered.map((a) => <option key={a.id} value={a.id}>{`${a.name}${a.identity?.client_id ? ` (${a.identity.client_id})` : ''} · ${a.status}`}</option>)}
                </optgroup>
              ) : null}
              {discovered.length ? (
                <optgroup label="Unmanaged">
                  {discovered.map((a) => <option key={a.id} value={a.id}>{`${a.name} · no client ID`}</option>)}
                </optgroup>
              ) : null}
              <option value="__unregistered">An unregistered caller</option>
            </select>
          </div>
          <div className="form-row">
            <div className="field">
              <label htmlFor="wi-user">On behalf of</label>
              <input type="text" id="wi-user" placeholder="No one: the agent alone" {...text('user')} />
            </div>
            <div className="field">
              <label htmlFor="wi-groups">Their groups</label>
              <input type="text" id="wi-groups" placeholder="support, /emea/sales" {...text('groups')} />
            </div>
          </div>
          <div className="form-row" hidden={isModel || isAgent}>
            <div className="field">
              <label htmlFor="wi-server">Tool server</label>
              <input type="text" id="wi-server" list="wi-server-list" {...text('server')} />
              <datalist id="wi-server-list">{servers.map((ts) => <option key={ts.name} value={ts.name} />)}</datalist>
            </div>
            <div className="field">
              <label htmlFor="wi-tool">Tool</label>
              <input type="text" id="wi-tool" list="wi-tool-list" {...text('tool')} />
              <datalist id="wi-tool-list">{tools.map((t, i) => <option key={i} value={t.name} />)}</datalist>
            </div>
          </div>
          <div className="form-row" hidden={!isModel}>
            <div className="field">
              <label htmlFor="wi-provider">Model provider</label>
              <input type="text" id="wi-provider" list="wi-provider-list" {...text('provider')} />
              <datalist id="wi-provider-list">{providers.map((p) => <option key={p.name} value={p.name} />)}</datalist>
            </div>
            <div className="field">
              <label htmlFor="wi-model">Model</label>
              <input type="text" id="wi-model" list="wi-model-list" {...text('model')} />
              <datalist id="wi-model-list">{models.map((m, i) => <option key={i} value={m} />)}</datalist>
            </div>
          </div>
          <div className="field" hidden={!isAgent}>
            <label htmlFor="wi-target">Agent called</label>
            <input type="text" id="wi-target" list="wi-target-list" {...text('target')} />
            <datalist id="wi-target-list">{serving.map((a) => <option key={a.id} value={a.name} />)}</datalist>
            <p className="hint">It calls the agent over A2A, through the gateway (SendMessage).</p>
          </div>
          {/* AgentGov checks the requests agents send each other, not their answers. */}
          <fieldset className="field" hidden={isAgent}>
            <legend className="field-label">Phase</legend>
            <div className="radio-row">
              <label className="check" htmlFor="wi-phase-request">
                <input type="radio" name="wi-phase" id="wi-phase-request" value="request" checked={phase === 'request'} onChange={() => set({ phase: 'request' })} />
                <span>{isModel ? 'Request (the prompt)' : 'Request (the tool call)'}</span>
              </label>
              <label className="check" htmlFor="wi-phase-response">
                <input type="radio" name="wi-phase" id="wi-phase-response" value="response" checked={phase === 'response'} onChange={() => set({ phase: 'response' })} />
                <span>{isModel ? 'Response (the answer)' : 'Response (the tool result)'}</span>
              </label>
            </div>
          </fieldset>
          <fieldset className="field">
            <legend className="field-label">Detections <span className="muted">(what Presidio and the detectors found)</span></legend>
            <label className="check" htmlFor="wi-pii"><input type="checkbox" id="wi-pii" value="pii" {...check('pii')} />Personal data (pii)</label>
            <label className="check" htmlFor="wi-secret"><input type="checkbox" id="wi-secret" value="secret" {...check('secret')} />Credentials (secret)</label>
            <label className="check" htmlFor="wi-injection" hidden={isAgent}>
              <input type="checkbox" id="wi-injection" {...check('injection')} />
              <span>{isModel ? 'Prompt injection in a tool result in the conversation' : 'Prompt injection in the result'}</span>
            </label>
            <label className="check" htmlFor="wi-jailbreak" hidden={!isModel}><input type="checkbox" id="wi-jailbreak" {...check('jailbreak')} />A jailbreak in the prompt</label>
            <label className="check" htmlFor="wi-tool-calls" hidden={!isModel}><input type="checkbox" id="wi-tool-calls" {...check('toolCalls')} />The conversation holds tool calls</label>
          </fieldset>
          <div className="btn-row">
            <button type="submit" className="btn btn--primary" disabled={busy}><Icon name="play" />Evaluate</button>
          </div>
        </form>
        <hr style={{ border: 0, borderTop: '1px solid var(--line)', margin: '4px 0', width: '100%' }} />
        <div className="stack" style={{ gap: 12 }} aria-live="polite">{result}</div>
      </div>
    </section>
  );
}

const EFFECTS: Record<string, [tone: string, icon: string, label: string, sub: string]> = {
  allow: ['good', 'check-circle', 'Allow', 'The call would go through.'],
  deny: ['critical', 'ban', 'Deny', 'The gateway would refuse the call.'],
  require_approval: ['warning', 'user-check', 'Require approval', 'The call would wait for a human approval.'],
};

// What OPA decided for the call, and why.
function WhatIfResult({ res, input, example }: { res: any; input: any; example: boolean }) {
  const r = res?.result;
  if (!r) {
    return <Callout tone="warning" icon="alert-circle">{`OPA returned no decision for ${res?.path || 'agentgov/mcp/decision'}. Check that the AgentGov policy bundle is loaded.`}</Callout>;
  }
  const [tone, ic, label, sub] = EFFECTS[r.effect] || ['neutral', 'info', humanize(r.effect), ''];
  return (
    <>
      {example ? <p className="example-tag">Example: the scenario filled in above, evaluated when the page loaded.</p> : null}
      <div className="effect" data-tone={tone}>
        <Icon name={ic} />
        <div><div className="effect-label">{label}</div><div className="effect-sub">{sub}</div></div>
      </div>
      {(r.reasons || []).length ? (
        <div className="stack" style={{ gap: 6 }}>
          <span className="field-label">Reasons</span>
          <ul className="reasons" role="list">
            {r.reasons.map((reason: string, i: number) => <li key={i}><Icon name={r.effect === 'deny' ? 'ban' : 'user-check'} /><span>{reason}</span></li>)}
          </ul>
        </div>
      ) : null}
      {(r.monitored || []).length ? (
        <div className="stack" style={{ gap: 6 }}>
          <span className="field-label">Monitored: would have been stopped</span>
          <ul className="reasons" role="list">
            {r.monitored.map((m: string, i: number) => <li key={i}><Icon name="eye" /><span>{m}</span></li>)}
          </ul>
        </div>
      ) : null}
      <Facts rows={[
        input.kind === 'a2a' ? null : ['Redact', (r.redact || []).length ? <div className="chip-row">{r.redact.map((c: string, i: number) => <PlainChip key={i} text={c} mono />)}</div> : 'Nothing'],
        ['Agent seen as', r.agent ? <>{r.agent.name}{` · ${r.agent.status} · ${r.agent.risk_level} risk`}</> : <span className="muted">Not a registered agent</span>],
        input.kind === 'a2a' ? ['Agent called', r.target ? `${r.target.name} · ${r.target.status}` : <span className="muted">Not a registered agent</span>] : null,
        ['Policy path', <code>{res.path}</code>],
      ]} />
      <details className="disclosure">
        <summary><Icon name="chevron" />Show OPA input and result</summary>
        <div className="stack" style={{ gap: 8 }}><JsonBlock value={{ input }} /><JsonBlock value={r} /></div>
      </details>
    </>
  );
}
