// One agent: who it is, what it may do, what it did, and what can be done to it.

import type { ReactNode } from 'react';
import { ask, type FieldSpec, type Values } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import {
  agentHref, Callout, Card, Chip, Copyable, EmptyState, Facts, JsonBlock, PlainChip, RiskChip, TimeEl, type FactRow,
} from '../components/ui';
import { api, getInfo } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { dateFmt, fmt, fullFmt, humanize, initials, plural, relTime } from '../lib/format';
import {
  formatGrants, formatLabels, formatModelAccess, orNull, parseBudget, parseGrants, parseLabels, parseList, parseModelAccess,
} from '../lib/forms';
import { refresh, type PageDef } from '../lib/router';
import { can, getMe, isScoped } from '../lib/session';
import {
  BLOCKABLE_SOURCES, featureModes, MODE_WORDS, NAME_HINT, PLATFORM_SOURCES, platformOf, RISK_TIERS,
} from '../lib/shared';
import { statusMeta, toneOf, TONE_COLOR } from '../lib/status';
import { AgentAccessCard, EntraAccessCard } from './accessPackages';
import { AgentFindingsCard, InstructionsCard } from './instructions';
import { isEntra, ISSUER_KINDS, issuerKind } from './issuers';
import { LedgerTable } from './ledger';
import { PlatformCard } from './platforms';
import { actsFor } from './policies';
import { ClassificationCard } from './register';
import { AgentRulesCard } from './rules';

export const LIFECYCLE: Record<string, any> = {
  approve: {
    label: 'Approve', icon: 'check', cls: 'btn--primary', tone: 'primary', confirm: 'Approve agent',
    text: 'The agent becomes active and can call the tools its blueprint and grants allow. Activation needs at least one sponsor.',
    done: (n: string) => `Approved ${n}. It is now active.`,
  },
  block: {
    label: 'Block (kill switch)', icon: 'power', cls: 'btn--danger', tone: 'danger', confirm: 'Block agent',
    text: 'This is the kill switch. The gateway refuses every call from this agent as soon as OPA loads the updated policy bundle, usually within seconds. You can unblock it later.',
    done: (n: string) => `Blocked ${n}. Its tool calls are refused.`,
  },
  unblock: {
    label: 'Unblock', icon: 'undo', cls: 'btn--primary', tone: 'primary', confirm: 'Unblock agent',
    text: 'Calls from this agent will be evaluated against policy again.',
    done: (n: string) => `Unblocked ${n}.`,
  },
  delete: {
    label: 'Delete', icon: 'trash', cls: 'btn--danger-quiet', tone: 'danger', confirm: 'Delete agent',
    text: 'The agent leaves the inventory and policy denies all of its calls. Deleted agents can be restored.',
    done: (n: string) => `Deleted ${n}.`,
  },
  restore: {
    label: 'Restore', icon: 'undo', cls: 'btn--primary', tone: 'primary', confirm: 'Restore agent',
    text: 'The agent comes back as pending approval. Approve it to make it active again.',
    done: (n: string) => `Restored ${n}. It is pending approval.`,
  },
  adopt: {
    label: 'Adopt', icon: 'user-check', cls: 'btn--primary', tone: 'primary', confirm: 'Adopt agent',
    text: 'Adopting brings this unmanaged agent under governance as a pending registration. Give it an owner, at least one sponsor and a blueprint, then approve it.',
    done: (n: string) => `Adopted ${n}. It is pending approval.`,
  },
};
// Blocking or deleting a platform agent changes AgentGov's registry, not the platform.
const PLATFORM_LIFECYCLE: Record<string, (p: string) => Record<string, any>> = {
  approve: (p) => ({ text: `The agent becomes active in AgentGov's registry, with an owner, sponsors and periodic review. It runs in ${p} either way. Activation needs at least one sponsor.` }),
  block: (p) => ({
    label: 'Block', confirm: 'Block in AgentGov',
    text: `This marks the agent as blocked in AgentGov's registry and ledger. It doesn't stop the agent in ${p}: while ${p} still runs it, an issue asks its people to stop it there, and closes once ${p} reports it stopped.`,
    done: (n: string, runsIn: string | null) => (runsIn ? `Blocked ${n} in AgentGov. It still runs in ${runsIn}: an issue asks its people to stop it there.` : `Blocked ${n} in AgentGov.`),
  }),
  unblock: (p) => ({ text: `The agent is no longer marked as blocked in AgentGov, and no issue asks to stop it in ${p} any more. This doesn't change ${p}.` }),
  delete: (p) => ({ text: `The agent leaves AgentGov's inventory but stays in ${p}. Deleted agents can be restored.` }),
  adopt: (p) => ({ text: `Adopting brings this ${p} agent under governance as a pending registration. Give it an owner and at least one sponsor, then approve it.` }),
};

// Unblocked, an agent is what it was when it was blocked: one that waited for approval waits
// again, and an unmanaged one is still unmanaged.
const UNBLOCKED_TO: Record<string, string> = {
  pending: 'It goes back to waiting for an administrator’s approval, as it was when it was blocked: its calls are refused until then.',
  discovered: 'It goes back to being unmanaged, as it was when it was blocked.',
};

function lifecycleSpec(a: any, action: string): any {
  const p = platformOf(a);
  const spec = p && PLATFORM_LIFECYCLE[action] ? { ...LIFECYCLE[action], ...PLATFORM_LIFECYCLE[action](p) } : LIFECYCLE[action];
  const back = action === 'unblock' ? UNBLOCKED_TO[a.blocked_from] : null;
  if (!back) return spec;
  // Not active again: say what it is, rather than that its calls are evaluated again.
  return { ...spec, text: p ? `${spec.text} ${back}` : back };
}

export const ACTIONS_BY_STATUS: Record<string, string[]> = {
  pending: ['approve', 'block', 'delete'],
  active: ['block', 'delete'],
  blocked: ['unblock', 'delete'],
  discovered: ['adopt', 'block', 'delete'],
  deleted: ['restore'],
};
const ATTESTABLE = new Set(['active', 'blocked', 'pending']);

interface AgentData {
  agent: any;
  // Each of these is what the API answered, or the error it failed with (shown on its card).
  entries: any;
  openFindings: any;
  instructions: any;
  usage: any;
  a2a: any;
  held: any;
  packages: any[];
  modes: Record<string, string>;
  matchedRules: any;
  entra: any;
  where: any;
}

export const agentPage: PageDef<AgentData> = {
  re: /^\/agents\/([^/]+)$/,
  nav: 'agents',
  title: 'Agent',
  load: async ({ match }) => {
    const ref = decodeURIComponent(match[1]);
    const agent = await api(`v1/agents/${encodeURIComponent(ref)}`);
    const [entries, openFindings, instructions, usage, a2a, held, packages, modes, matchedRules] = await Promise.all([
      api(`v1/ledger?agent=${encodeURIComponent(agent.id)}&limit=12`).catch((e) => e),
      api(`v1/findings?status=open&agent=${encodeURIComponent(agent.id)}`).catch((e) => e),
      api(`v1/agents/${encodeURIComponent(agent.id)}/instructions`).catch((e) => e),
      api(`v1/models/usage?agent=${encodeURIComponent(agent.id)}&days=7`).catch((e) => e),
      api(`v1/agents/${encodeURIComponent(agent.id)}/a2a`).catch((e) => e),
      api(`v1/agents/${encodeURIComponent(agent.id)}/access-packages`).catch((e) => e),
      api('v1/access-packages').catch(() => []),
      // Organisation-wide: not for those with roles for some teams only.
      isScoped() ? {} : featureModes().catch(() => ({})),
      api(`v1/agents/${encodeURIComponent(agent.id)}/rules`).catch(() => []),
    ]);
    // What Microsoft Entra ID Governance assigns its Entra identity, when it has one.
    const entra = agent.external_ids?.entra_agent_id
      ? await api(`v1/agents/${encodeURIComponent(agent.id)}/entra-access-packages`).catch((e) => e)
      : null;
    // Agents on Microsoft 365 or Copilot Studio don't use the gateway: show what their platform reports.
    const views = agent.platforms || [];
    const where = views.length && agent.status !== 'deleted' ? await platformActionTarget(agent) : null;
    return { agent, entries, openFindings, instructions, usage, a2a, held, packages, modes, matchedRules, entra, where };
  },
  View: AgentView,
  titleOf: (data) => data.agent.name,
};

function AgentView({ data }: { data: AgentData }) {
  const { agent, entries, openFindings, instructions, usage, a2a, held, packages, modes, matchedRules, entra, where } = data;
  const views: any[] = agent.platforms || [];
  const main = views.length ? views.map((v, i) => <PlatformCard key={i} a={agent} v={v} where={where} />) : [
    <PermissionsCard key="permissions" a={agent} />,
    <AgentAccessCard key="access" agent={agent} rows={held} packages={packages} mode={modes['access-packages']} />,
    <AgentModelsCard key="models" a={agent} usage={usage} />,
    <AgentA2ACard key="a2a" a={agent} view={a2a} />,
  ];
  // With threat detection enforcing, AgentGov's policies decide about its tool calls.
  const enforced = views.some((v) => v.source === 'copilot-studio') && modes['copilot-studio-threat-detection'] === 'enforce';
  return (
    <div className="page">
      <AgentHeader a={agent} />
      <div className="detail-grid">
        <div className="stack">
          {main}
          <InstructionsCard a={agent} view={instructions} />
          <AgentLedgerCard a={agent} entries={entries} />
          {views.length ? null : <AgentCardCard a={agent} />}
        </div>
        <div className="stack">
          <RiskCard a={agent} enforced={enforced} />
          <PeopleCard a={agent} />
          <AttestationCard a={agent} />
          <ClassificationCard a={agent} />
          <IdentityCard a={agent} />
          {entra instanceof Error || !entra ? null : <EntraAccessCard agent={agent} view={entra} />}
          <AgentRulesCard rows={matchedRules} />
          <AgentFindingsCard list={openFindings} />
        </div>
      </div>
    </div>
  );
}

function AgentHeader({ a }: { a: any }) {
  const [, , statusLabel] = statusMeta('agent', a.status);
  const showReason = a.status_reason && a.status !== 'active';
  return (
    <header className="detail-head">
      <nav className="crumbs" aria-label="Breadcrumb">
        <a href="#/agents">Agents</a><Icon name="chevron" /><span aria-current="page">{a.name}</span>
      </nav>
      <div className="title-row"><h1 tabIndex={-1}>{a.name}</h1><Chip kind="agent" value={a.status} /><RiskChip risk={a.risk} /></div>
      {a.description ? <p style={{ color: 'var(--ink-2)', maxWidth: '72ch' }}>{a.description}</p> : null}
      {showReason ? (
        <Callout tone={toneOf('agent', a.status)} icon="info"><span><strong>{`${statusLabel}: `}</strong>{a.status_reason}</span></Callout>
      ) : null}
      {a.status === 'blocked' && a.still_runs_in ? (
        <Callout tone="warning" icon="triangle">
          <span>
            <strong>{`Blocked in AgentGov only: ${a.still_runs_in} still runs it. `}</strong>
            {`An issue asks its people to stop it there, and closes once ${a.still_runs_in} reports it stopped.`}
          </span>
        </Callout>
      ) : null}
      <AgentToolbar a={a} />
    </header>
  );
}

// Sponsors attest their own agents, whatever their role: signed in as themselves, by the
// email address their provider vouches for (me.person; an API key is nobody); admins any agent.
function mayAttest(a: any): boolean {
  if (!ATTESTABLE.has(a.status)) return false;
  const person = String(getMe()?.person || '').toLowerCase();
  const sponsor = Boolean(person) && (a.sponsors || []).some((s: unknown) => String(s).toLowerCase() === person);
  return can('admin', a) || sponsor;
}

function AgentToolbar({ a }: { a: any }) {
  const allowed = can('admin', a) ? ACTIONS_BY_STATUS[a.status] || []
    : can('contain', a) ? (ACTIONS_BY_STATUS[a.status] || []).filter((x) => x === 'block' || x === 'unblock') : [];
  const buttons = allowed.map((action) => {
    const spec = lifecycleSpec(a, action);
    return (
      <button key={action} type="button" className={`btn ${spec.cls}`} onClick={() => runLifecycle(a, action)}>
        <Icon name={spec.icon} />{spec.label}
      </button>
    );
  });
  if (mayAttest(a)) {
    buttons.push(<button key="attest" type="button" className="btn" onClick={() => runAttest(a)}><Icon name="shield-check" />Attest</button>);
  }
  if (can('admin', a) && a.status !== 'deleted') {
    buttons.unshift(<button key="edit" type="button" className="btn" onClick={guarded(() => editAgent(a))}><Icon name="edit" />Edit</button>);
  }
  // Gone for good: administrators for every team.
  if (can('admin') && a.status === 'deleted') {
    buttons.push(<button key="purge" type="button" className="btn btn--danger-quiet" onClick={() => purgeAgent(a)}><Icon name="trash" />Delete permanently</button>);
  }
  if (!buttons.length) return null;
  return <div className="toolbar" role="group" aria-label="Agent actions">{buttons}</div>;
}

/** Approve, block, unblock, delete, restore or adopt an agent, after asking. */
export async function runLifecycle(a: any, action: string): Promise<void> {
  const spec = lifecycleSpec(a, action);
  const fields: FieldSpec[] = [];
  if (action === 'adopt') {
    // Its maker on its platform, where AgentGov knows them.
    const maker = a.suggested_owner;
    fields.push(
      {
        id: 'owner', label: 'Owner', placeholder: 'Team or person accountable for the agent', value: a.owner || maker || '',
        hint: maker && !a.owner ? `Suggested: ${maker}, ${suggestedWhy(a)}. Change it if someone else should own it.` : null,
      },
      { id: 'sponsors', label: 'Sponsors', placeholder: 'alice@example.com, bob@example.com', value: (a.sponsors?.length ? a.sponsors : maker ? [maker] : []).join(', '), hint: 'Separate people with commas. Approval needs at least one sponsor.' },
    );
    // Blueprints grant gateway tools, which agents on other platforms don't use.
    if (!platformOf(a)) {
      const blueprints: any[] = await api('v1/blueprints').catch(() => []);
      fields.push({
        id: 'blueprint', label: 'Blueprint', type: 'select', value: a.blueprint || '',
        options: [{ value: '', label: 'No blueprint' }, ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))],
      });
    }
  }
  // A platform agent can be blocked (or released) in its own platform too, as the signed-in admin.
  const where = action === 'block' || action === 'unblock' ? await platformActionTarget(a) : null;
  let text = spec.text;
  if (where && getMe()?.microsoft) {
    // The checkbox covers the platform, so the text says only what AgentGov does.
    text = action === 'block' ? "This marks the agent as blocked in AgentGov's registry and ledger." : 'The agent is no longer marked as blocked in AgentGov.';
    fields.push({
      id: 'in_platform', type: 'checkbox', value: true,
      label: action === 'block' ? where.blockLabel : where.unblockLabel,
      hint: `AgentGov does this in ${where.name} as you, so ${where.name} records it under your name.`,
    });
  } else if (where) {
    text += ` To do that from here, sign in to AgentGov with Microsoft Entra ID.`;
  }
  fields.push({ id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger.' });
  const done = await ask<any>({
    title: `${spec.label.replace(' (kill switch)', '')} ${a.name}?`,
    text, tone: spec.tone, iconName: spec.icon, confirm: spec.confirm, fields, busy: 'Working…',
    submit: async (values) => {
      const body: Record<string, any> = {};
      if (values.reason) body.reason = values.reason;
      if (action === 'adopt') {
        if (values.owner) body.owner = values.owner;
        const sponsors = values.sponsors.split(',').map((x: string) => x.trim()).filter(Boolean);
        if (sponsors.length) body.sponsors = sponsors;
        if (values.blueprint) body.blueprint = values.blueprint;
      }
      // AgentGov first: if it refuses (an unblock needs a sponsor), the platform is left
      // alone. If the platform then refuses, the agent is still blocked where it runs.
      const changed = await api(`v1/agents/${encodeURIComponent(a.id)}/${action}`, { method: 'POST', body });
      // Blocked here, the platform that still runs it, where an issue asks to stop it.
      const runsIn = changed?.still_runs_in || null;
      if (!values.in_platform) return { inPlatform: false, runsIn };
      try {
        await api(`v1/agents/${encodeURIComponent(a.id)}/platform/${action}`, { method: 'POST' });
        return { inPlatform: true };
      } catch (err) {
        return { inPlatform: false, platformError: err, runsIn };
      }
    },
  });
  if (!done) return;
  if (done.platformError) {
    const verb = action === 'block' ? 'Blocked' : 'Unblocked';
    const handedOff = done.runsIn ? ` An issue asks its people to stop it in ${done.runsIn}.` : '';
    toast(`${verb} ${a.name} in AgentGov. ${done.platformError.message}${handedOff}`, { tone: 'critical' });
  } else {
    toast(done.inPlatform ? (action === 'block' ? where.blocked(a.name) : where.unblocked(a.name)) : spec.done(a.name, done.runsIn));
  }
  void refreshBadges();
  await refresh();
}

/** Where Block can also act for a platform agent, when signed-in admins may act in Microsoft. */
async function platformActionTarget(a: any): Promise<any> {
  const views = (a.platforms || []).filter((v: any) => BLOCKABLE_SOURCES.has(v.source));
  const info = await getInfo();
  if (!views.length || !info?.microsoft_admin_actions || !can('admin')) return null;
  // The control plane quarantines the Copilot Studio agent when there is one (no licence needed).
  if (views.some((v: any) => v.source === 'copilot-studio')) {
    return {
      name: 'Copilot Studio', source: 'copilot-studio',
      blockLabel: 'Also quarantine it in Copilot Studio', unblockLabel: 'Also release it from quarantine in Copilot Studio',
      blocked: (n: string) => `Blocked ${n} in AgentGov and quarantined it in Copilot Studio.`,
      unblocked: (n: string) => `Unblocked ${n} in AgentGov and released it from quarantine in Copilot Studio.`,
    };
  }
  return {
    name: 'Microsoft 365', source: 'microsoft-365',
    blockLabel: 'Also block it in Microsoft 365', unblockLabel: 'Also unblock it in Microsoft 365',
    blocked: (n: string) => `Blocked ${n} in AgentGov and in Microsoft 365.`,
    unblocked: (n: string) => `Unblocked ${n} in AgentGov and in Microsoft 365.`,
  };
}

/** Block (or unblock) an agent on its platform (Copilot Studio, Microsoft 365). */
export async function platformBlock(a: any, where: any, blocking: boolean): Promise<void> {
  const studio = where.source === 'copilot-studio';
  const verb = blocking ? (studio ? 'Quarantine' : 'Block') : (studio ? 'Release' : 'Unblock');
  const done = await ask({
    title: `${verb} ${a.name} in ${where.name}?`,
    text: blocking
      ? (studio ? 'Copilot Studio stops the agent on every channel; its makers can still open and test it. ' : 'Microsoft 365 blocks the agent for everyone in the organisation. ')
        + `AgentGov does this as you and records it in the evidence ledger. The agent's status in AgentGov doesn't change.`
      : `${where.name} lets people use the agent again. AgentGov does this as you and records it in the evidence ledger.`,
    tone: blocking ? 'danger' : 'primary', iconName: blocking ? 'ban' : 'undo',
    confirm: `${verb} in ${where.name}`, busy: 'Working…',
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}/platform/${blocking ? 'block' : 'unblock'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(blocking ? `${studio ? 'Quarantined' : 'Blocked'} ${a.name} in ${where.name}.` : `${studio ? 'Released' : 'Unblocked'} ${a.name} in ${where.name}.`);
  await refresh();
}

async function runAttest(a: any) {
  const values = await ask({
    title: `Attest ${a.name}?`,
    text: "Confirm that this agent is still needed and its access is still right. The next review date comes from the blueprint's attestation period (90 days without a blueprint).",
    iconName: 'shield-check', confirm: 'Attest',
    fields: [{ id: 'note', label: 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
  });
  if (!values) return;
  try {
    const updated = await api(`v1/agents/${encodeURIComponent(a.id)}/attest`, { method: 'POST', body: values.note ? { note: values.note } : {} });
    const due = updated.attestation?.expires_at;
    toast(`Attested ${a.name}.${due ? ` Next review due ${dateFmt.format(new Date(due))}.` : ''}`);
    await refresh();
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
}

async function recalcRisk(a: any) {
  try {
    const r = await api(`v1/agents/${encodeURIComponent(a.id)}/risk/refresh`, { method: 'POST' });
    toast(`Risk recalculated for ${a.name}: ${r.score} of 100 (${r.level}).`);
    void refreshBadges();
    await refresh();
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
}

/** Register an agent (no `a`) or edit one. Resolves to the saved agent, or null. */
export async function agentForm(a: any): Promise<any> {
  const [blueprints, issuers, teams]: any[][] = await Promise.all([
    api('v1/blueprints'), isScoped() ? [] : api('v1/identity-issuers').catch(() => []), api('v1/teams').catch(() => []),
  ]);
  const editing = Boolean(a);
  const identity = a?.workload_identity;
  // An agent linked to Microsoft Entra Agent ID: its tokens' subject is its object ID.
  const entra = a?.external_ids?.entra_agent_id;
  // A public client has no identity of its own: people sign in to it.
  const issuerOf = (v: Values) => (v.client_type === 'public' ? null : issuers.find((i) => i.name === v.workload_issuer));
  const firstIssuer = issuerOf({ client_type: a?.client_type || 'service', workload_issuer: identity?.issuer || '' });
  // The subject's example, for the issuer chosen; hidden, the field keeps the last one.
  let subjectExample: string | undefined;
  // Who gets its tokens: the agent itself, or people who sign in to it (a public client);
  // and how the agent authenticates, offered once there's an issuer to choose.
  const authentication: FieldSpec[] = [
    { type: 'section', label: 'Authentication' },
    {
      id: 'client_type', label: 'Its tokens are for', type: 'select', value: a?.client_type || 'service',
      options: [
        { value: 'service', label: 'The agent itself (a confidential client)' },
        { value: 'public', label: "People who sign in to it on their machines, such as developers' MCP clients (a public client)" },
      ],
      hint: 'A public client has no secret: people sign in to it, and it acts for them with their own token.',
    },
    {
      id: 'redirect_uris', label: 'Sign-ins return to', mono: true, value: (a?.redirect_uris || []).join(', '), placeholder: 'http://127.0.0.1/*, http://localhost/*',
      hint: 'Where its sign-in may return, separated by commas, with * only at the end. Empty: the machine itself, at any port, where MCP clients such as VS Code and Claude Code listen for it.',
      hidden: (v) => v.client_type !== 'public',
    },
    ...(issuers.length || identity ? [
      {
        id: 'workload_issuer', label: 'Authenticates with', type: 'select', value: identity?.issuer || '',
        options: [
          { value: '', label: 'A client secret' },
          ...issuers.map((i) => ({ value: i.name, label: `Its own identity from ${i.name} (${issuerKind(i.kind)}${i.status === 'blocked' ? ', blocked' : ''})` })),
        ],
        hint: 'An identity it already has, such as a Kubernetes service account, needs no secret to store or rotate.',
        hidden: (v: Values) => v.client_type === 'public',
      } as FieldSpec,
      {
        id: 'workload_subject', label: 'Subject', mono: true,
        value: identity?.subject || (firstIssuer && isEntra(firstIssuer) && entra ? entra : ''),
        hint: 'Its subject at the issuer: the sub claim of its tokens there.',
        hidden: (v: Values) => !issuerOf(v),
        placeholder: (v: Values) => {
          const issuer = issuerOf(v);
          if (issuer) {
            subjectExample = issuer.kind === 'spiffe'
              ? `${issuer.issuer}/ns/agents/sa/${a?.name || 'support-bot'}`
              : ISSUER_KINDS[issuer.kind]?.[1] || '';
          }
          return subjectExample;
        },
      } as FieldSpec,
    ] : []),
  ];
  const tiers = RISK_TIERS.map((t) => ({ value: t, label: humanize(t) }));
  const fields: FieldSpec[] = [
    editing ? null : {
      id: 'name', label: 'Name', required: true, mono: true, placeholder: 'support-bot',
      hint: `${NAME_HINT} The agent gets the OAuth client agent-<name>.`,
    },
    { id: 'description', label: 'Description', type: 'textarea', value: a?.description || '' },
    { type: 'section', label: 'Accountability' },
    {
      type: 'row',
      fields: [
        { id: 'owner', label: 'Owner', value: a?.owner || '', placeholder: 'Team or person', datalist: teams.map((t) => t.name) },
        { id: 'environment', label: 'Environment', value: a?.environment || '', placeholder: 'prod', datalist: ['prod', 'staging', 'dev'] },
      ],
    },
    {
      id: 'sponsors', label: 'Sponsors', value: (a?.sponsors || []).join(', '), placeholder: 'alice@example.com',
      hint: 'People who vouch for the agent, separated by commas. Approval needs at least one unless the blueprint waives it.',
    },
    {
      id: 'team', label: 'Team', type: 'select', value: a?.team || '',
      options: [{ value: '', label: "Its blueprint's team (or the default team)" }, ...teams.map((t) => ({ value: t.name, label: t.name }))],
      hint: 'Issues about the agent go to its owner, then its sponsors, then this team.',
    },
    ...authentication,
    { type: 'section', label: 'Access' },
    {
      id: 'blueprint', label: 'Blueprint', type: 'select', value: a?.blueprint || '',
      options: [{ value: '', label: 'No blueprint' }, ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))],
      hint: "The agent gets the blueprint's tool grants, sponsor rule and review period.",
    },
    {
      id: 'permissions', label: 'Extra tool grants', type: 'code', rows: 3, value: formatGrants(a?.permissions), placeholder: 'crm: search_customers, get_*',
      hint: 'Added to the blueprint\'s grants. One server per line; tool names can use * wildcards, and * alone means every tool.',
    },
    {
      id: 'model_access', label: 'Extra model access', type: 'code', rows: 2, value: formatModelAccess(a?.model_access), placeholder: 'openai: gpt-4o-mini',
      hint: "Added to the blueprint's model access. One provider per line; model names can use * wildcards.",
    },
    { id: 'daily_token_budget', label: 'Daily token budget', type: 'number', min: 0, value: a?.daily_token_budget ?? '', hint: "Input and output tokens per UTC day. Empty: the blueprint's budget." },
    {
      id: 'risk_tier', label: 'Declared risk tier', type: 'select', value: a?.risk_tier || '',
      options: editing ? tiers : [{ value: '', label: "The blueprint's tier (medium without one)" }, ...tiers],
    },
    { type: 'section', label: 'Agent to agent' },
    {
      id: 'a2a_url', label: 'A2A endpoint', value: a?.a2a_url || '', placeholder: 'http://billing-agent:9600', mono: true,
      hint: 'Where it serves A2A (its JSON-RPC endpoint). Other agents then call it at /a2a/<name> on the gateway, as their grants allow.',
    },
    {
      id: 'a2a_protection', label: 'Calls around the gateway are stopped by', type: 'select', value: a?.a2a_protection || '',
      options: [
        { value: '', label: 'Nothing we know of' },
        { value: 'network', label: 'The network: only the gateway can reach it' },
        { value: 'delegation', label: "The agent: it refuses calls without the gateway's delegation" },
      ],
      hint: "AgentGov checks only the calls that come through its gateway. Say what stops calls straight to the A2A endpoint: AgentGov can test it, and tells the agent's owners when it doesn't.",
    },
    {
      id: 'agent_access', label: 'Extra agents it may call', value: (a?.agent_access || []).join(', '), placeholder: 'billing-agent, kb-*', mono: true,
      hint: "Added to the agents its blueprint may call over A2A, separated by commas; names can use * wildcards.",
    },
    { type: 'section', label: 'Details' },
    {
      type: 'row',
      fields: [
        { id: 'framework', label: 'Framework', value: a?.framework || '' },
        { id: 'platform', label: 'Platform', value: a?.platform || '' },
      ],
    },
    { id: 'models', label: 'Models', value: (a?.models || []).join(', '), hint: 'Separated by commas.' },
    { id: 'labels', label: 'Labels', value: formatLabels(a?.labels), placeholder: 'team=cx, cost-center=42', mono: true },
    editing ? null : { id: 'approve', label: 'Approve now', type: 'checkbox', hint: 'Otherwise the agent waits in Pending review until an admin approves it.' },
  ];
  return ask<any>({
    title: editing ? `Edit ${a.name}` : 'Register an agent',
    text: editing
      ? 'Changes are recorded in the evidence ledger, and the gateway enforces them as soon as OPA loads the updated policy bundle.'
      : 'Approved agents get their own OAuth client in Keycloak and can call the tools they are granted.',
    iconName: editing ? 'edit' : 'agents', confirm: editing ? 'Save changes' : 'Register agent', fields,
    // An issuer chosen whose subjects are Entra object IDs: the agent's own, until one is typed.
    onChange: (v, changed) => {
      if (changed !== 'client_type' && changed !== 'workload_issuer') return undefined;
      const issuer = issuerOf(v);
      return issuer && isEntra(issuer) && entra && !v.workload_subject ? { workload_subject: entra } : undefined;
    },
    submit: async (v) => {
      const isPublic = v.client_type === 'public';
      if (!isPublic && v.workload_issuer && !v.workload_subject) throw new Error('Give its subject at the issuer, or choose a client secret.');
      const body: Record<string, any> = {
        description: v.description,
        owner: orNull(v.owner),
        environment: orNull(v.environment),
        sponsors: parseList(v.sponsors),
        team: v.team || null,
        blueprint: v.blueprint || null,
        permissions: parseGrants(v.permissions),
        model_access: parseModelAccess(v.model_access),
        daily_token_budget: parseBudget(v.daily_token_budget),
        agent_access: parseList(v.agent_access),
        a2a_url: orNull(v.a2a_url),
        a2a_protection: v.a2a_protection || null,
        framework: orNull(v.framework),
        platform: orNull(v.platform),
        models: parseList(v.models),
        labels: parseLabels(v.labels),
        client_type: v.client_type,
        redirect_uris: isPublic ? parseList(v.redirect_uris) : [],
      };
      if ('workload_issuer' in v) {
        body.workload_identity = v.workload_issuer && !isPublic ? { issuer: v.workload_issuer, subject: v.workload_subject } : null;
      }
      // Left unchanged, the tier follows the blueprint (as the API does).
      if (v.risk_tier && v.risk_tier !== a?.risk_tier) body.risk_tier = v.risk_tier;
      if (editing) return api(`v1/agents/${encodeURIComponent(a.id)}`, { method: 'PATCH', body, ifMatch: a.version });
      return api('v1/agents', { method: 'POST', body: { name: v.name, ...body, approve: v.approve } });
    },
  });
}

/** Register an agent, from its form. */
export async function registerAgent(): Promise<void> {
  const created = await agentForm(null);
  if (!created) return;
  toast(`Registered ${created.name}. ${created.status === 'active' ? 'It is active.' : 'It is pending review.'}`);
  void refreshBadges();
  window.location.hash = agentHref(created.id);
}

async function editAgent(a: any) {
  const saved = await agentForm(a);
  if (!saved) return;
  toast(`Saved ${saved.name}.`);
  await refresh();
}

async function purgeAgent(a: any) {
  const done = await ask({
    title: `Delete ${a.name} permanently?`,
    text: 'The agent and its OAuth client are removed and cannot be restored. Its ledger entries are kept.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete permanently', busy: 'Deleting…',
    fields: [{ id: 'confirm_name', label: `Type ${a.name} to confirm`, required: true, mono: true, match: a.name, mismatch: `Type ${a.name} exactly to confirm.` }],
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${a.name} permanently.`);
  window.location.hash = '#/agents';
}

/** How an agent with a workload identity authenticates: its issuer's token, no secret. */
async function agentSignIn(a: any) {
  let creds;
  try {
    creds = await api(`v1/agents/${encodeURIComponent(a.id)}/credentials`, { method: 'POST', body: {} });
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
    return;
  }
  // Straight to the gateway, where it takes the issuer's tokens itself
  // (docs/agent-identity.md#straight-to-the-gateway).
  const direct = creds.gateway ? (
    <>
      <h3 className="dialog-section">Straight to the gateway</h3>
      <p className="muted">{"The gateway takes the issuer's tokens itself: the agent calls it with its token for this audience as the bearer token, without Keycloak."}</p>
      <Facts rows={[
        ['Issuer', creds.gateway.issuer],
        ['Subject', <Copyable text={creds.subject} label="subject" />],
        ["Its token's audience", <Copyable text={creds.gateway.audience} label="audience" />],
        ['Gateway', <Copyable text={creds.gateway.url} label="gateway URL" />],
      ]} />
    </>
  ) : null;
  if (!creds.token_endpoint) {
    await ask({
      title: `How ${a.name} authenticates`,
      text: `With a token from ${creds.issuer} whose subject is its own, instead of a client secret.`,
      iconName: 'key', confirm: 'Done', cancel: null, wide: true, extra: direct,
    });
    return;
  }
  const request = [
    `POST ${creds.token_endpoint}`,
    'grant_type=client_credentials',
    `client_assertion_type=${creds.assertion_type}`,
    "client_assertion=<the issuer's token>",
  ].join('\n');
  await ask({
    title: `How ${a.name} authenticates`,
    text: `With a token from ${creds.issuer} whose subject is its own, instead of a client secret. Keycloak checks the token against the issuer's keys and gives back an AgentGov access token for the gateway.`,
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: (
      <>
        <Facts rows={[
          ['Client ID', <Copyable text={creds.client_id} label="client ID" />],
          ['Issuer', creds.issuer],
          ['Subject', <Copyable text={creds.subject} label="subject" />],
          ["Its token's audience", <Copyable text={creds.assertion_audience} label="audience" />],
          ['Token endpoint', <Copyable text={creds.token_endpoint} label="token endpoint" />],
          ['Gateway audience', <Copyable text={creds.audience} label="gateway audience" />],
        ]} />
        <pre className="kv-pre" tabIndex={0}>{request}</pre>
        {direct}
      </>
    ),
  });
}

/** Where people sign in to a public client, as their MCP clients find it. */
async function publicSignIn(a: any) {
  let creds;
  try {
    creds = await api(`v1/agents/${encodeURIComponent(a.id)}/credentials`, { method: 'POST', body: {} });
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
    return;
  }
  await ask({
    title: `How people sign in to ${a.name}`,
    text: "Their MCP client finds where to sign in from the gateway, once Developers sign in at the gateway is on, and asks them for this client ID if it can't register itself. They sign in in their browser, and the client acts for them with their own token, which the gateway takes for this agent and for them.",
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: (
      <Facts rows={[
        ['Client ID', <Copyable text={creds.client_id} label="client ID" />],
        ['Issuer', <Copyable text={creds.issuer} label="issuer" />],
        ['Sign-ins return to', <span className="mono">{(creds.redirect_uris || []).join(', ')}</span>],
        ['Authorization endpoint', <Copyable text={creds.authorization_endpoint} label="authorization endpoint" />],
        ['Token endpoint', <Copyable text={creds.token_endpoint} label="token endpoint" />],
        ['Gateway audience', <Copyable text={creds.audience} label="gateway audience" />],
      ]} />
    ),
  });
}

/** Show the agent's OAuth client credentials, after issuing a new secret if `rotate`. */
async function agentCredentials(a: any, rotate: boolean) {
  const creds = await ask<any>({
    title: rotate ? `Rotate the client secret of ${a.name}?` : `Show the credentials of ${a.name}?`,
    text: rotate
      ? 'Keycloak issues a new secret and the current one stops working at once, so update the agent straight away. The rotation is recorded in the evidence ledger.'
      : 'The client secret is shown in the next dialog. Viewing it is recorded in the evidence ledger.',
    tone: rotate ? 'danger' : 'primary', iconName: 'key', confirm: rotate ? 'Rotate secret' : 'Show credentials',
    busy: rotate ? 'Rotating…' : 'Loading…',
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}/credentials`, { method: 'POST', body: { rotate } }),
  });
  if (!creds) return;
  await ask({
    title: `${rotate ? 'New credentials' : 'Credentials'} for ${a.name}`,
    text: 'The agent exchanges these for 5-minute access tokens with the client credentials grant. Keep the secret in a secret store, not in code.',
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: (
      <Facts rows={[
        ['Client ID', <Copyable text={creds.client_id} label="client ID" />],
        ['Client secret', <Copyable text={creds.client_secret} label="client secret" />],
        ['Token endpoint', <Copyable text={creds.token_endpoint} label="token endpoint" />],
        ['Audience', <Copyable text={creds.audience} label="audience" />],
      ]} />
    ),
  });
}

function PermissionsCard({ a }: { a: any }) {
  const effective: any[] = a.effective_permissions || [];
  const own = new Map<string, Set<string>>((a.permissions || []).map((g: any) => [g.server, new Set(g.tools)]));
  const broad = effective.some((g) => g.server === '*' && g.tools.includes('*'));
  const list = effective.length ? (
    <ul className="perm-list" role="list">
      {effective.map((g, i) => (
        <li key={i}>
          <span className="perm-server">{g.server === '*' ? '* (any server)' : g.server}</span>
          <div className="chip-row">
            {g.tools.map((t: string, j: number) => {
              const direct = own.get(g.server)?.has(t);
              return <PlainChip key={j} text={t} mono tone={direct ? 'accent' : null} title={direct ? 'Granted to this agent directly' : `From blueprint ${a.blueprint || ''}`.trim()} />;
            })}
          </div>
        </li>
      ))}
    </ul>
  ) : <p className="muted small">No tools are granted. Policy denies every tool call from this agent.</p>;
  return (
    <Card title="Permissions" sub="Effective grants: the blueprint plus grants made to this agent. Tool patterns are globs.">
      <Facts rows={[
        ['Blueprint', a.blueprint ? <a href="#/policies">{a.blueprint}</a> : <span className="muted">None assigned</span>],
        ['Declared risk tier', humanize(a.risk_tier)],
        ['Acts for', actsFor(a)],
      ]} />
      {broad ? <Callout tone="warning" icon="triangle">This agent may call every tool on every server (*/*). Replace the wildcard with the tools it needs.</Callout> : null}
      {list}
      {own.size ? <p className="hint">Highlighted patterns are granted to this agent directly; the others come from its blueprint.</p> : null}
    </Card>
  );
}

function AgentModelsCard({ a, usage }: { a: any; usage: any }) {
  const access: any[] = a.effective_model_access || [];
  const own = new Map<string, Set<string>>((a.model_access || []).map((g: any) => [g.provider, new Set(g.models)]));
  const budget = a.effective_daily_token_budget;
  const today = usage instanceof Error ? null : (usage.today || []).find((b: any) => b.agent_id === a.id);
  const used = today?.used_today ?? 0;
  const totals = usage instanceof Error ? null : usage.totals;
  const tone = budget != null && used >= budget ? 'critical' : 'accent';
  return (
    <Card title="Models" sub="Models it may call through the gateway, and what it used in the last 7 days">
      {access.length ? (
        <ul className="perm-list" role="list">
          {access.map((g, i) => (
            <li key={i}>
              <span className="perm-server">{g.provider}</span>
              <div className="chip-row">
                {g.models.map((m: string, j: number) => {
                  const direct = own.get(g.provider)?.has(m);
                  return <PlainChip key={j} text={m} mono tone={direct ? 'accent' : null} title={direct ? 'Granted to this agent directly' : `From blueprint ${a.blueprint || ''}`.trim()} />;
                })}
              </div>
            </li>
          ))}
        </ul>
      ) : <p className="muted small">No model access. Policy refuses its model calls through the gateway.</p>}
      <Facts rows={[
        ['Daily token budget', budget == null ? <span className="muted">None</span> : `${fmt(budget)} tokens${a.daily_token_budget == null ? ' (from its blueprint)' : ''}`],
        ['Used today', budget == null ? `${fmt(used)} tokens` : (
          <div className="stack" style={{ gap: 4 }}>
            {`${fmt(used)} of ${fmt(budget)} tokens`}
            <div className="meter" role="img" aria-label={`${fmt(used)} of ${fmt(budget)} tokens used today`} style={{ background: `var(--${tone === 'critical' ? 'critical' : 'neutral'}-tint)` }}>
              <span style={{ width: `${budget ? Math.min(100, (used / budget) * 100) : 100}%`, background: TONE_COLOR[tone] }} />
            </div>
          </div>
        )],
        totals ? ['Last 7 days', `${plural(totals.calls, 'call')}, ${fmt(totals.input_tokens + totals.output_tokens)} tokens${totals.cost_usd ? `, $${totals.cost_usd.toFixed(2)}` : ''}${totals.refused ? `, ${fmt(totals.refused)} refused` : ''}`] : null,
      ]} />
    </Card>
  );
}

function RiskCard({ a, enforced = false }: { a: any; enforced?: boolean }) {
  const risk = a.risk || {};
  const tone = toneOf('risk', risk.level);
  const platform = platformOf(a);
  return (
    <Card
      title="Risk"
      sub={platform ? `Posture, instructions, and how ${platform} has it set up` : 'Posture, instructions, and runtime signals from the last 24 hours'}
      actions={can('admin', a) ? [<button key="recalc" type="button" className="btn btn--sm" onClick={() => recalcRisk(a)}><Icon name="refresh" />Recalculate</button>] : null}
    >
      <div className="risk-head">
        <span className="hero-figure">{fmt(risk.score ?? 0)}</span><span className="of">of 100</span><Chip kind="risk" value={risk.level || 'low'} />
      </div>
      <div className="meter" role="img" aria-label={`Risk score ${risk.score ?? 0} of 100`} style={{ background: `var(--${tone}-tint)` }}>
        <span style={{ width: `${Math.min(100, risk.score ?? 0)}%`, background: TONE_COLOR[tone] }} />
      </div>
      {(risk.factors || []).length ? (
        <ul className="factor-list" role="list">
          {risk.factors.map((f: any, i: number) => (
            <li key={i}>
              <span>{f.factor}{f.detail ? <span className="muted">{` · ${f.detail}`}</span> : null}</span>
              <span className="factor-points">{`+${f.points}`}</span>
            </li>
          ))}
        </ul>
      ) : <p className="muted small">No risk factors.</p>}
      <p className="hint">
        {platform && !enforced
          ? `Levels: 25 medium, 50 high, 75 critical. High and critical risk raise an alert; ${platform} keeps running the agent.`
          : `Levels: 25 medium, 50 high, 75 critical. Policy blocks agents at critical risk${enforced ? ": Copilot Studio asks AgentGov before each of this agent's tool calls" : ''}.`}
      </p>
    </Card>
  );
}

function PersonRow({ name, role }: { name: string; role: string }) {
  return (
    <li className="person">
      <span className="avatar" aria-hidden="true">{initials(name)}</span>
      <span className="person-text"><span>{name}</span><span className="role">{role}</span></span>
    </li>
  );
}

// Someone a platform names as an agent's maker or owner, as AgentGov knows them.
export function makerName(m: any): string {
  if (m.name && m.email) return `${m.name} (${m.email})`;
  return m.name || m.email || `Entra ID ${m.entra_id}`;
}

export function makerRole(m: any): string {
  const where = PLATFORM_SOURCES[`platform:${m.source}`] || m.source;
  const roles = m.roles || [];
  const words = roles.includes('owner') && roles.includes('creator') ? `Made it, and owns it in ${where}`
    : roles.includes('owner') ? `Owns it in ${where}` : `Made it in ${where}`;
  let note = null;
  if (m.left) note = `left ${relTime(m.left_at)}`;
  else if (m.enabled === false) note = 'account disabled';
  else if (m.entra_id && !m.looked_up) note = 'not looked up yet';
  else if (m.entra_id && !m.known) note = 'not a user in the directory';
  return note ? `${words} · ${note}` : words;
}

// One line for a maker where there is room for one: the list, the adopt dialog.
export function makerLine(m: any): string {
  const where = PLATFORM_SOURCES[`platform:${m.source}`] || m.source;
  const note = m.left ? ' (left)' : m.enabled === false ? ' (account disabled)' : '';
  return (m.roles || []).includes('creator') ? `Made by ${makerName(m)}${note}` : `Owner in ${where}: ${makerName(m)}${note}`;
}

// Who the person adopting an agent suggests is to it: "who owns it in Copilot Studio".
function suggestedWhy(a: any): string {
  const pick = (a.makers || []).find((m: any) => (m.email || '').toLowerCase() === a.suggested_owner);
  return pick && (pick.roles || []).includes('owner') ? `who owns it in ${platformOf(a) || 'its platform'}` : 'who made it';
}

function MakersBlock({ a }: { a: any }) {
  const makers: any[] = a.makers || [];
  if (!makers.length) return null;
  const unknown = makers.some((m) => m.entra_id && !m.looked_up);
  return (
    <>
      <ul className="people" role="list">{makers.map((m, i) => <PersonRow key={i} name={makerName(m)} role={makerRole(m)} />)}</ul>
      {unknown ? (
        <p className="hint">
          {'AgentGov knows people by name once it can look them up: '}
          <a href="#/platforms">connect Microsoft Entra users, or upload a list of users</a>{'.'}
        </p>
      ) : null}
    </>
  );
}

function PeopleCard({ a }: { a: any }) {
  const managed = a.status !== 'discovered';
  const sponsors: string[] = a.sponsors || [];
  // The owner and sponsors who have left: issues go past them.
  const gone: Record<string, any> = Object.fromEntries((a.left || []).map((g: any) => [g.name.toLowerCase(), g]));
  const role = (name: string, word: string) => {
    const g = gone[String(name).toLowerCase()];
    return g ? `${word} · ${g.how === 'left' ? 'has left' : 'account disabled'}` : word;
  };
  return (
    <Card title="Owner and sponsors" sub="The accountable team and the people who vouch for this agent">
      {(a.left || []).length ? (
        <Callout tone="warning" icon="alert-circle">
          {`${a.left.map((g: any) => (g.how === 'left' ? `${g.name} has left` : `${g.name}'s account is disabled`)).join('; ')}, as Microsoft Entra ID says: its issues go to the next people responsible for it. Name others.`}
        </Callout>
      ) : null}
      {a.owner ? <ul className="people" role="list"><PersonRow name={a.owner} role={role(a.owner, 'Owner')} /></ul> : (
        <Callout tone={managed ? 'warning' : 'neutral'} icon={managed ? 'alert-circle' : 'info'}>
          {managed ? 'No owner. Assign an owning team or person.'
            : a.suggested_owner ? `Unmanaged agents have no owner until someone adopts them. Adopting it suggests ${a.suggested_owner}, ${suggestedWhy(a)}.`
              : 'Unmanaged agents have no owner until someone adopts them.'}
        </Callout>
      )}
      <MakersBlock a={a} />
      {sponsors.length ? <ul className="people" role="list">{sponsors.map((p, i) => <PersonRow key={i} name={p} role={role(p, 'Sponsor')} />)}</ul> : (
        <Callout tone={managed ? 'warning' : 'neutral'} icon={managed ? 'alert-circle' : 'info'}>
          No sponsor. An agent needs at least one sponsor before it can be activated.
        </Callout>
      )}
      {a.team ? <ul className="people" role="list"><PersonRow name={a.team} role="Team: issues escalate to it" /></ul> : null}
    </Card>
  );
}

function AttestationCard({ a }: { a: any }) {
  const att = a.attestation || {};
  let status: ReactNode;
  if (!att.expires_at) {
    status = <Callout tone="neutral" icon="info">No review is scheduled. A review date is set when the agent is approved or attested.</Callout>;
  } else {
    const days = (new Date(att.expires_at).getTime() - Date.now()) / 86400000;
    if (days < 0) {
      status = <Callout tone="critical" icon="octagon"><span><strong>{'Review overdue. '}</strong>{`The attestation expired ${relTime(att.expires_at)}.`}</span></Callout>;
    } else if (days < 14) {
      status = <Callout tone="warning" icon="clock"><span><strong>{'Review due soon. '}</strong>{`Due ${relTime(att.expires_at)}.`}</span></Callout>;
    } else {
      status = (
        <Callout tone="good" icon="check-circle">
          <span>{'Next review due '}<strong>{dateFmt.format(new Date(att.expires_at))}</strong>{` (${relTime(att.expires_at)}).`}</span>
        </Callout>
      );
    }
  }
  return (
    <Card
      title="Attestation"
      sub="Periodic confirmation by a sponsor that the agent is still needed"
      actions={mayAttest(a) ? [<button key="attest" type="button" className="btn btn--sm" onClick={() => runAttest(a)}><Icon name="shield-check" />Attest</button>] : null}
    >
      {status}
      <Facts rows={[
        ['Last attested', att.attested_at ? <><TimeEl iso={att.attested_at} />{att.attested_by ? ` by ${att.attested_by}` : ''}</> : <span className="muted">Never</span>],
        ['Review due', att.expires_at ? <time dateTime={att.expires_at} title={fullFmt.format(new Date(att.expires_at))}>{dateFmt.format(new Date(att.expires_at))}</time> : null],
      ]} />
    </Card>
  );
}

function IdentityCard({ a }: { a: any }) {
  const id = a.identity || {};
  const labels = Object.entries(a.labels || {});
  const external = Object.entries(a.external_ids || {});
  const workload = a.workload_identity;
  // Keycloak only issues secrets to active agents; one with a workload identity has none.
  let credentialActions: ReactNode[] | null = can('admin', a) && a.status === 'active' && id.client_id ? [
    <button key="show" type="button" className="btn btn--sm" onClick={guarded(() => agentCredentials(a, false))}><Icon name="key" />Show secret</button>,
    <button key="rotate" type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => agentCredentials(a, true))}><Icon name="refresh" />Rotate</button>,
  ] : null;
  // Its issuer's token authenticates it: through Keycloak, or straight to a gateway that
  // takes the issuer's tokens (without Keycloak, it has no client there).
  if (workload && can('admin', a) && a.status === 'active') {
    credentialActions = [<button key="sign-in" type="button" className="btn btn--sm" onClick={guarded(() => agentSignIn(a))}><Icon name="key" />How it authenticates</button>];
  }
  const isPublic = a.client_type === 'public';
  if (credentialActions && isPublic) {
    credentialActions = [<button key="sign-in" type="button" className="btn btn--sm" onClick={guarded(() => publicSignIn(a))}><Icon name="key" />How people sign in</button>];
  }
  const platform = platformOf(a);
  let noClient = a.status === 'discovered' ? 'Not issued (unmanaged)' : 'Not issued';
  if (platform) noClient = "Not needed: it doesn't use the gateway";
  const rows: FactRow[] = [
    platform ? null : ['Provider', humanize(id.provider || 'none')],
    ['Client ID', id.client_id ? <Copyable text={id.client_id} label="client ID" /> : <span className="muted">{noClient}</span>],
    platform ? null : ['Authenticates with', isPublic
      ? 'Nothing of its own: people sign in to it (a public client)'
      : workload
        ? <>{'Its own identity from '}<a href="#/access">{workload.issuer}</a></>
        : 'A client secret'],
    isPublic ? ['Sign-ins return to', <span className="mono">{(a.redirect_uris.length ? a.redirect_uris : ['http://127.0.0.1/*', 'http://localhost/*']).join(', ')}</span>] : null,
    workload ? ['Subject', <Copyable text={workload.subject} label="subject" />] : null,
    platform ? null : ['Synced', id.synced_at ? <TimeEl iso={id.synced_at} /> : <span className="muted">Not synced yet</span>],
    ['Agent ID', <Copyable text={a.id} label="agent ID" />],
    ['Source', a.source],
    ['Framework', a.framework],
    ['Environment', a.environment],
    a.platform ? ['Platform', a.platform] : null,
    (a.models || []).length ? ['Models', <div className="chip-row">{a.models.map((m: string, i: number) => <PlainChip key={i} text={m} mono />)}</div>] : null,
    labels.length ? ['Labels', <div className="chip-row">{labels.map(([k, v]) => <PlainChip key={k} text={`${k}=${v}`} mono />)}</div>] : null,
    Object.keys(a.control_modes || {}).length ? ['Controls for it', (
      <div className="stack-tight">
        {Object.entries(a.control_modes as Record<string, any>).map(([key, c]) => (
          <div key={key}><a href="#/features">{key}</a>{`: ${(MODE_WORDS[c.mode] || c.mode).toLowerCase()} (${c.why})`}</div>
        ))}
      </div>
    )] : null,
    external.length ? ['External IDs', <div className="chip-row">{external.map(([k, v]) => <PlainChip key={k} text={`${k}: ${v}`} mono />)}</div>] : null,
    ['Created', <><TimeEl iso={a.created_at} />{a.created_by ? ` by ${a.created_by}` : ''}</>],
    ['Last seen', <TimeEl iso={a.last_seen_at} empty="Never" />],
    a.deleted_at ? ['Deleted', <TimeEl iso={a.deleted_at} />] : null,
  ];
  return (
    <Card
      title="Identity"
      sub={platform ? `Runs on ${platform}, outside AgentGov's gateway` : 'The OAuth client the gateway authenticates this agent with'}
      actions={credentialActions}
    >
      {id.error ? <Callout tone="critical" icon="octagon"><strong>{'Identity out of sync. '}</strong>{id.error}</Callout> : null}
      <Facts rows={rows} />
    </Card>
  );
}

// Calls around the gateway: what its owners say stops calls straight to its A2A endpoint,
// and what AgentGov found when it last called it itself.
const AROUND_SAYS: Record<string, string> = {
  network: 'The network: only the gateway can reach it',
  delegation: "The agent: it refuses calls without the gateway's delegation",
};
const AROUND_FOUND: Record<string, [tone: string | null, iconName: string, label: string]> = {
  refused: ['good', 'shield-check', 'It refused the test call'],
  accepted: ['critical', 'alert-circle', 'It took the test call'],
  unreachable: [null, 'info', "AgentGov couldn't reach it"],
  inconclusive: ['warning', 'triangle', 'Inconclusive'],
};
function aroundGateway(around: any): ReactNode {
  const says = AROUND_SAYS[around.protection];
  const test = around.test;
  const [tone, iconName, label] = test ? (AROUND_FOUND[test.state] || [null, 'info', test.state]) : [];
  return (
    <div className="stack" style={{ gap: 4 }}>
      {says ? <span>{`Stopped by ${says.charAt(0).toLowerCase()}${says.slice(1)}`}</span>
        : <span className="muted">{"Its owners haven't said what stops calls straight to it"}</span>}
      {test ? (
        <div>
          <PlainChip text={label} tone={tone} iconName={iconName} />{' '}<span className="muted small">{`${test.detail}, `}</span><TimeEl iso={test.checked_at} />
        </div>
      ) : (
        <span className="muted small">{around.mode === 'test' ? 'Not tested yet: the next posture scan tests it.' : `Not tested (calls-around-gateway is ${around.mode}).`}</span>
      )}
    </div>
  );
}

// Agent to agent: where other agents call it, whom it may call, and who may call it.
function AgentA2ACard({ a, view }: { a: any; view: any }) {
  if (view instanceof Error) {
    return <Card title="Agent to agent"><Callout tone="critical" icon="alert-circle">{view.message}</Callout></Card>;
  }
  const names = (list: string[]) => (list.length ? (
    <div className="chip-row">
      {list.map((name, i) => <a key={i} className="chip chip--plain" href={`#/agents/${encodeURIComponent(name)}`}>{name}</a>)}
    </div>
  ) : <span className="muted">No agent</span>);
  const rows: FactRow[] = [
    view.serves ? ['Serves A2A at', <code className="break">{view.a2a_url}</code>] : null,
    view.published ? ['Agents call it at', <Copyable text={view.url} label="A2A address" />] : null,
    view.published ? ['Its card', <Copyable text={view.card_url} label="agent card address" />] : null,
    view.serves && !view.published ? ['On the gateway', <span className="muted">{`Not published: ${view.unpublished}`}</span>] : null,
    ['May call', names(view.may_call)],
    view.agent_access.length ? ['Its grants', <span className="chip-row">{view.agent_access.map((p: string, i: number) => <PlainChip key={i} text={p} mono />)}</span>] : null,
    view.serves ? ['Called by', names(view.called_by)] : null,
    view.serves ? ['Around the gateway', aroundGateway(view.around_gateway)] : null,
  ];
  const idle = !view.serves && !view.may_call.length && !view.agent_access.length;
  return (
    <Card
      title="Agent to agent"
      sub="Calls between agents through the gateway (A2A) are checked by policy, one by one; the agent called gets who handed the work down, with the person at its head. Calls straight to an agent skip the gateway."
    >
      {idle
        ? <EmptyState title="It doesn't serve or call other agents" text={can('admin', a) ? 'Give it an A2A endpoint, or agents it may call, with Edit.' : null} />
        : <Facts rows={rows} />}
    </Card>
  );
}

function AgentCardCard({ a }: { a: any }) {
  const ac = a.agent_card;
  if (!ac) {
    return (
      <Card title="A2A agent card" sub="Skills and interfaces the agent advertises">
        <p className="muted small">This agent has not published an A2A agent card.</p>
      </Card>
    );
  }
  const skills: any[] = Array.isArray(ac.skills) ? ac.skills : [];
  return (
    <Card title="A2A agent card" sub={<>{ac.name || a.name}{ac.version ? ` · version ${ac.version}` : ''}</>}>
      {skills.length ? (
        <ul className="factor-list" role="list">
          {skills.map((sk, i) => (
            <li key={i}>
              <span><strong>{sk.name || sk.id}</strong>{sk.description ? <span className="muted">{` · ${sk.description}`}</span> : null}</span>
              <span className="chip-row">{(sk.tags || []).map((t: string, j: number) => <PlainChip key={j} text={t} />)}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <details className="disclosure">
        <summary><Icon name="chevron" />Show agent card JSON</summary>
        <JsonBlock value={ac} />
      </details>
    </Card>
  );
}

function AgentLedgerCard({ a, entries }: { a: any; entries: any }) {
  const body = entries instanceof Error
    ? <Callout tone="critical" icon="alert-circle">{`The ledger couldn't be loaded. ${entries.message}`}</Callout>
    : entries.length
      ? <LedgerTable entries={entries} compact />
      : <EmptyState title="No ledger entries" text="Lifecycle changes and tool-call decisions for this agent appear here." />;
  return (
    <Card
      title="Recent activity"
      sub="Latest evidence-ledger entries for this agent"
      actions={[<a key="ledger" className="btn btn--sm btn--ghost" href={`#/ledger?agent=${encodeURIComponent(a.name)}`}>Open in ledger<Icon name="arrow" /></a>]}
      flush={!(entries instanceof Error) && entries.length > 0}
    >
      {body}
    </Card>
  );
}
