// Who and what can use AgentGov: people who sign in with single sign-on, API keys, and the
// identity issuers whose tokens agents authenticate with.

import { Callout, PageHead, RefreshButton } from '../components/ui';
import { api, getInfo } from '../lib/api';
import type { PageDef } from '../lib/router';
import { featureModes } from '../lib/shared';
import { ApiKeysCard, IssuersCard, RoleGrantsCard, SignInsCard } from './issuers';

interface AccessData {
  view: any;
  keys: any[];
  issuers: any[];
  features: Record<string, string>;
  info: any;
}

export const accessPage: PageDef<AccessData> = {
  re: /^\/access$/,
  nav: 'access',
  title: 'Access',
  load: async () => {
    const [view, keys, issuers, features, info] = await Promise.all([
      api('v1/access'), api<any[]>('v1/apikeys'), api<any[]>('v1/identity-issuers'),
      featureModes().catch((): Record<string, string> => ({})), getInfo(),
    ]);
    return { view, keys, issuers, features, info };
  },
  View: ({ data: { view, keys, issuers, features, info } }) => (
    <div className="page">
      <PageHead
        title="Access"
        sub="Who and what can use AgentGov: people who sign in with single sign-on, API keys for the CLI, CI pipelines and other automation, and the identity issuers whose tokens agents authenticate with instead of client secrets."
        actions={[<RefreshButton key="refresh" />]}
      />
      {view.bootstrap_token ? (
        <Callout tone="neutral" icon="key">
          <span>
            <strong>{'The bootstrap admin token is set. '}</strong>
            Anyone who has it is an admin. Keep it for setup and emergencies, and give people and automation their own roles.
          </span>
        </Callout>
      ) : null}
      {view.provider?.problem ? (
        <Callout tone="critical" icon="octagon">
          <span><strong>{"People can't sign in now: "}</strong>{view.provider.problem}</span>
        </Callout>
      ) : null}
      <SignInsCard view={view} />
      <RoleGrantsCard view={view} />
      <ApiKeysCard keys={keys} policy={view.api_keys || {}} />
      {features['workload-identity'] === 'off' ? (
        <Callout tone="warning" icon="power">
          <span>
            <strong>{"Agents' own identities are off: "}</strong>
            {"no issuer is trusted, so agents with a workload identity can't authenticate. "}
            <a href="#/features">Features</a>.
          </span>
        </Callout>
      ) : null}
      <IssuersCard issuers={issuers} keycloak={Boolean(info?.identity_provider)} />
    </div>
  ),
};
