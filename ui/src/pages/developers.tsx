// Developer tools: the MCP servers developers' MCP clients may use (an MCP registry for
// GitHub Copilot and VS Code), how developers sign in to the ones on the gateway, and the
// MCP servers developers set up on their machines.

import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import {
  agentHref, Callout, Card, Copyable, EmptyState, Facts, PageHead, PlainChip, RefreshButton, TimeEl,
} from '../components/ui';
import { api, saveDownload } from '../lib/api';
import { fmt, humanize, plural } from '../lib/format';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { featureModes } from '../lib/shared';
import { toolserverForm } from './toolservers';

type Sighting = any;

const SIGHTING_STATUS: Record<string, [label: string, tone: string, icon: string, title: string]> = {
  approved: ['Approved', 'good', 'check-circle', 'An approved tool server'],
  bypass: ['Past the gateway', 'critical', 'triangle', "A gateway server's own address: calls skip the gateway's controls"],
  blocked: ['Blocked', 'critical', 'ban', 'A blocked tool server'],
  unapproved: ['Not approved', 'warning', 'triangle', 'Not an approved tool server'],
};

interface DevelopersData {
  registry: any;
  sightings: Sighting[];
  features: Record<string, string>;
  agentList: any[];
}

export const developersPage: PageDef<DevelopersData> = {
  re: /^\/developers$/,
  nav: 'developers',
  title: 'Developer tools',
  load: async () => {
    const [registry, sightings, features, agentList] = await Promise.all([
      api('v1/mcp/registry'), api('v1/mcp/sightings'), featureModes().catch(() => ({} as Record<string, string>)), api('v1/agents').catch(() => []),
    ]);
    return { registry, sightings, features, agentList };
  },
  View: ({ data: { registry, sightings, features, agentList } }) => (
    <div className="page">
      <PageHead
        title="Developer tools"
        sub="Which MCP servers developers' MCP clients may use, served as an MCP registry for GitHub Copilot and VS Code, how developers sign in to the ones on the gateway, and which ones developers have set up on their machines."
        actions={[<RefreshButton key="refresh" />]}
      />
      <RegistryCard registry={registry} />
      <SignInCard clients={agentList.filter((a) => a.client_type === 'public')} features={features} />
      <SightingsCard groups={sightings} features={features} />
    </div>
  ),
};

/** Developers' MCP clients on the gateway, with their own tokens: the public clients they sign in to. */
function SignInCard({ clients, features }: { clients: any[]; features: Record<string, string> }) {
  const on = features['developer-sign-in'] === 'on';
  return (
    <Card
      title="Signing in at the gateway"
      sub="Developers' MCP clients reach the tool servers on the gateway with the developer's own token: the gateway tells them where to sign in, and they sign in to an agent registered as a public client, which acts for them."
      flush={Boolean(clients.length)}
    >
      {on ? null : (
        <Callout tone="info" icon="power">
          <span>
            <strong>Off: </strong>{"the gateway doesn't tell MCP clients where to sign in. Turn on "}<code>developer-sign-in</code>
            {' on the '}<a href="#/features">Features</a>{' page.'}
          </span>
        </Callout>
      )}
      {clients.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">Agents developers sign in to</caption>
            <thead>
              <tr>{['Agent', 'Client ID', 'Sign-ins return to', 'Status'].map((c) => <th key={c} scope="col">{c}</th>)}</tr>
            </thead>
            <tbody>
              {clients.map((a) => (
                <tr key={a.id}>
                  <td data-label="Agent"><a href={agentHref(a.id)}>{a.name}</a>{a.blueprint ? <div className="cell-sub">{a.blueprint}</div> : null}</td>
                  <td data-label="Client ID"><Copyable text={a.identity.client_id} label="client ID" /></td>
                  <td data-label="Sign-ins return to">
                    <code className="break">{(a.redirect_uris.length ? a.redirect_uris : ['http://127.0.0.1/*', 'http://localhost/*']).join(', ')}</code>
                  </td>
                  <td data-label="Status">{humanize(a.status)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          title="No agent for developers to sign in to"
          text="Register an agent whose tokens are for people who sign in to it (a public client), with a blueprint whose agents act for people."
        />
      )}
    </Card>
  );
}

function RegistryCard({ registry }: { registry: any }) {
  const servers: any[] = registry.servers || [];
  const where = (server: any) => [
    ...(server.remotes || []).map((r: any, i: number) => <code key={`remote-${i}`} className="break">{r.url}</code>),
    ...(server.packages || []).map((pk: any, i: number) => (
      <PlainChip key={`package-${i}`} text={`${pk.registryType}:${pk.identifier}${pk.version ? `@${pk.version}` : ''}`} mono />
    )),
  ];
  const download = guarded(async () => {
    await saveDownload('v1/mcp/managed-settings', 'managed-settings.json');
    toast('Saved managed-settings.json: the same servers as an allowlist, by URL and command.');
  });
  return (
    <Card
      title="MCP registry"
      sub="Tool servers listed for developers. In GitHub's AI controls (MCP), set this as the MCP registry URL and choose Registry only: Copilot then runs only these servers."
      actions={<button type="button" className="btn" onClick={download}><Icon name="download" />managed-settings.json</button>}
    >
      {registry.enabled ? null : (
        <Callout tone="warning" icon="power">
          <span>
            <strong>The registry is off: </strong>
            {"developers' clients can't read it. It is served without credentials, as they read it; turn on "}<code>mcp-registry</code>
            {' on the '}<a href="#/features">Features</a>{' page.'}
          </span>
        </Callout>
      )}
      <Facts rows={[
        ['Registry URL', <Copyable text={registry.url} label="registry URL" />],
        ['Names', <span><code>{`${registry.namespace}/<server>`}</code></span>],
      ]} />
      {servers.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">Servers in the MCP registry</caption>
            <thead>
              <tr>{['Name', 'Version', 'Developers connect to', 'Status'].map((c) => <th key={c} scope="col">{c}</th>)}</tr>
            </thead>
            <tbody>
              {servers.map((entry, i) => (
                <tr key={i}>
                  <td data-label="Name"><code className="break">{entry.server.name}</code></td>
                  <td data-label="Version">{entry.server.version}</td>
                  <td data-label="Developers connect to"><div className="stack" style={{ gap: 4 }}>{where(entry.server)}</div></td>
                  <td data-label="Status">
                    {entry.server._meta?.['dev.agentgov/server']?.throughGateway
                      ? <PlainChip text="Through the gateway" tone="good" iconName="shield" />
                      : <PlainChip text="Developers only" iconName="developers" />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          title="No tool servers are listed for developers"
          text="Edit a tool server and tick Developers, or register one only for developers, with its address or its packages."
        />
      )}
    </Card>
  );
}

function SightingsCard({ groups, features }: { groups: Sighting[]; features: Record<string, string> }) {
  const command = 'agentgov mcp scan --report';
  const body = groups.length ? (
    <div className="table-wrap">
      <table className="data rtable">
        <caption className="sr-only">{"MCP servers on developers' machines"}</caption>
        <thead>
          <tr>
            {['Status', 'Server', 'Set up as', 'Machines', 'Last reported', ''].map((c, i) => (
              <th key={i} scope="col" className={c === 'Machines' ? 'num' : undefined}>{c || <span className="sr-only">Actions</span>}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {groups.map((g, i) => {
            const [label, tone, ic, title] = SIGHTING_STATUS[g.status] || [humanize(g.status), 'neutral', 'info', ''];
            const what = g.url || (g.command || []).join(' ') || g.identity;
            return (
              <tr key={i}>
                <td data-label="Status"><PlainChip text={label} tone={tone} iconName={ic} title={title} />{g.server ? <div className="cell-sub">{g.server}</div> : null}</td>
                <td data-label="Server"><code className="break">{what}</code></td>
                <td data-label="Set up as"><span className="break">{g.names.join(', ')}</span><div className="cell-sub">{g.clients.join(', ')}</div></td>
                <td data-label="Machines" className="num">{fmt(g.machines)}<div className="cell-sub">{plural(g.users, 'person', 'people')}</div></td>
                <td data-label="Last reported"><TimeEl iso={g.last_seen_at} /></td>
                <td data-label="">
                  {g.status === 'unapproved' && can('admin') && registerDraft(g) ? (
                    <button type="button" className="btn btn--sm" onClick={guarded(() => registerSighting(g))}><Icon name="plus" />Register</button>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  ) : (
    <EmptyState
      title="No reports yet"
      text={<span>{'Developers, or your device management, run '}<code>{command}</code>{' with an API key of the registrar role.'}</span>}
    />
  );
  return (
    <Card
      title="Set up on developers' machines"
      sub="The MCP servers in VS Code, Copilot, Claude, Cursor and other clients, as developers report them, against the approved tool servers. Credentials never leave their machines: an address comes by its host, with a hash of its path."
      actions={<Copyable text={command} label="scan command" />}
      flush={Boolean(groups.length)}
    >
      {features['mcp-discovery'] === 'off' ? (
        <Callout tone="warning" icon="power">
          <span><strong>Reports are off. </strong>{'Turn on '}<code>mcp-discovery</code>{' on the '}<a href="#/features">Features</a>{' page.'}</span>
        </Callout>
      ) : null}
      {body}
    </Card>
  );
}

// A tool server registration started from what developers set up: their address, or
// the package they run. An address is reported by host, with a hash of its path, which
// the administrator completes.
function registerDraft(g: Sighting): any {
  const [kind, ...rest] = g.identity.split(':');
  const value = rest.join(':');
  const name = (g.names[0] || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
  if (kind === 'url') return { name, url: (g.url || value).split('#')[0], gateway: false, developers: true };
  if (['npm', 'pypi', 'oci'].includes(kind)) return { name, gateway: false, developers: true, packages: [{ registry_type: kind, identifier: value }] };
  return null;
}

async function registerSighting(g: Sighting) {
  const created = await toolserverForm(null, registerDraft(g));
  if (!created) return;
  toast(`Registered ${created.name}. Its issue resolves once AgentGov compares the reports again.`);
  await refresh();
}
