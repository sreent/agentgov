// The admin center: signing in, then the menu and the page.

import { useCallback, useEffect, useState } from 'react';
import { DialogHost, closeDialog } from '../components/dialog';
import { Icon } from '../components/Icon';
import { Toasts, clearToasts } from '../components/toast';
import { api, getInfo, whenSignInExpires } from '../lib/api';
import { clearBadges, refreshBadges, useBadges } from '../lib/badges';
import { fmt } from '../lib/format';
import {
  getMe, getToken, home, inSession, isPerson, isScoped, mayOpen, personPages, roleName, signedIn, signedOut,
  SSO_ERRORS, TEAM_PAGES, type Me,
} from '../lib/session';
import { currentTheme, nextTheme } from '../lib/theme';
import { PageHost } from './PageHost';
import { SignIn } from './SignIn';

type Phase = { name: 'starting' } | { name: 'signin'; message?: string } | { name: 'app'; signedInNow: boolean };

export function App() {
  const [phase, setPhase] = useState<Phase>({ name: 'starting' });

  const toSignin = useCallback((message?: string) => {
    signedOut();
    clearToasts();
    closeDialog();
    clearBadges();
    setPhase({ name: 'signin', message });
  }, []);

  // Signed in: their first page, unless the address names one.
  const enter = useCallback((who: Me, { keepToken, signedInNow }: { keepToken: boolean; signedInNow: boolean }) => {
    signedIn(who, { keepToken });
    const { hash } = window.location;
    if (!hash || hash === '#' || hash === '#/') window.history.replaceState(null, '', home());
    setPhase({ name: 'app', signedInNow });
  }, []);

  const signOut = useCallback(async (message: string) => {
    if (inSession()) {
      // End the control plane's session, then the identity provider's.
      try {
        const out = await api<{ logout_url?: string }>('auth/logout', { method: 'POST', signingIn: true });
        if (out?.logout_url) {
          window.location.assign(out.logout_url);
          return;
        }
      } catch {
        /* already ended or unreachable: show the sign-in page anyway */
      }
    }
    toSignin(message);
  }, [toSignin]);

  // Resume a token kept in this tab, or a single sign-on session (auth/session answers 200
  // either way, so a visitor who is not signed in causes no failed request); otherwise the
  // sign-in page, with the reason a single sign-on attempt failed.
  useEffect(() => {
    whenSignInExpires(() => {
      if (inSession()) toSignin('Your session has ended. Sign in again.');
      else if (getToken()) toSignin('Your API token was rejected. It may have been revoked or rotated. Sign in again.');
    });
    const ssoError = new URLSearchParams(window.location.search).get('sso_error');
    if (ssoError) window.history.replaceState(null, '', window.location.pathname + window.location.hash);
    const failed = ssoError ? SSO_ERRORS[ssoError] || SSO_ERRORS.provider : undefined;
    const start = async () => {
      const token = getToken();
      try {
        const who = token ? await api<Me>('v1/me', { signingIn: true }) : await api<Me>('auth/session', { signingIn: true });
        if (!token && !who.signed_in) {
          setPhase({ name: 'signin', message: failed });
          return;
        }
        if (!mayOpen(who)) {
          if (!token) await api('auth/logout', { method: 'POST', signingIn: true }).catch(() => null);
          toSignin(`Your role (${roleName(who.role)}) can't open the admin center. Use an admin, approver, secops or auditor account.`);
          return;
        }
        enter(who, { keepToken: Boolean(token), signedInNow: false });
      } catch (err: any) {
        if (token && err.status === 401) toSignin('Your API token was rejected. It may have been revoked or rotated. Sign in again.');
        else if (failed) setPhase({ name: 'signin', message: failed });
        else setPhase({ name: 'signin', message: err.status === 401 ? undefined : err.message });
      }
    };
    void start();
  }, [toSignin, enter]);

  return (
    <>
      {phase.name === 'signin' ? (
        <SignIn message={phase.message} onSignedIn={(who) => enter(who, { keepToken: true, signedInNow: true })} />
      ) : null}
      {phase.name === 'app' ? <Shell focusFirst={phase.signedInNow} onSignOut={() => void signOut('You signed out.')} /> : null}
      <Toasts />
      <DialogHost />
    </>
  );
}

// The menu: its groups, and in each the pages, by their menu key.
const MENU: { group: string | null; items: [nav: string, href: string, icon: string, label: string][] }[] = [
  { group: null, items: [['overview', '#/overview', 'overview', 'Overview']] },
  { group: 'Work', items: [['approvals', '#/approvals', 'approvals', 'Approvals'], ['findings', '#/findings', 'findings', 'Issues']] },
  { group: 'Agents', items: [['agents', '#/agents', 'agents', 'Agents'], ['map', '#/map', 'map', 'Agent map'], ['platforms', '#/platforms', 'platforms', 'Platforms']] },
  {
    group: 'Gateway',
    items: [['toolservers', '#/toolservers', 'toolservers', 'Tool servers'], ['models', '#/models', 'models', 'Models'],
      ['policies', '#/policies', 'policies', 'Policies'], ['developers', '#/developers', 'developers', 'Developer tools']],
  },
  {
    group: 'Evidence',
    items: [['ledger', '#/ledger', 'ledger', 'Ledger'], ['compliance', '#/ledger/compliance', 'compliance', 'Compliance'],
      ['register', '#/ledger/register', 'register', 'Register']],
  },
  {
    group: 'Settings',
    items: [['teams', '#/findings/teams', 'teams', 'Teams'], ['secops', '#/secops', 'secops', 'Security operations'],
      ['access', '#/access', 'access', 'Access'], ['features', '#/features', 'features', 'Features']],
  },
];

const THEME_ICONS = { system: 'monitor', light: 'sun', dark: 'moon' };

function Shell({ focusFirst, onSignOut }: { focusFirst: boolean; onSignOut: () => void }) {
  const [active, setActive] = useState('');
  const [title, setTitle] = useState('');
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState(currentTheme);
  const [meta, setMeta] = useState('');
  const badges = useBadges();
  const me = getMe();

  // People without an AgentGov role have only their issues and approvals; those with roles
  // for some teams only, those teams' agents and what hangs off them.
  const shows = (nav: string) => !(isPerson() && !personPages().includes(nav)) && !(isScoped() && !TEAM_PAGES.includes(nav));

  const onPage = useCallback((nav: string, pageTitle: string) => {
    setActive(nav);
    setTitle(pageTitle);
    setOpen(false);
  }, []);

  useEffect(() => {
    void refreshBadges();
    let live = true;
    void getInfo().then(async (info) => {
      if (!info || !live) return;
      const who = me ? ` · signed in as ${me.actor}${me.via === 'session' ? ' (single sign-on)' : ''}` : '';
      // Whether the control plane reaches OPA now, not only whether it is set up.
      const components = isScoped() ? null : await api('v1/components').catch(() => null);
      const opa = components?.control_plane?.opa;
      const opaWords = !info.opa ? 'not configured' : opa ? (opa.ok ? 'reachable' : 'unreachable') : 'set up';
      if (live) setMeta(`AgentGov ${info.version} · ${info.identity_provider ? 'agents in Keycloak' : 'no Keycloak for agents'} · OPA ${opaWords}${who}`);
    });
    return () => {
      live = false;
    };
  }, [me]);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        document.getElementById('nav-toggle')?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    const nav = document.getElementById('nav');
    (nav?.querySelector<HTMLElement>('a[aria-current="page"]') || nav?.querySelector<HTMLElement>('a'))?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  const close = () => {
    setOpen(false);
    document.getElementById('nav-toggle')?.focus();
  };
  const badge = (count: number, tone: string, word: string) => (
    <span className="nav-badge" data-tone={tone} hidden={!count}>
      {count ? fmt(count) : ''}<span className="sr-only">{` ${word}`}</span>
    </span>
  );

  return (
    <>
      <a className="skip-link" href="#main" onClick={(e) => {
        // The skip link must not change the address: that would go to a page named "main".
        e.preventDefault();
        document.getElementById('main')?.focus();
      }}>Skip to content</a>
      <div id="shell" className="shell">
        <header className="topbar">
          <button type="button" className="icon-btn" id="nav-toggle" aria-controls="nav" aria-expanded={open}
            aria-label={open ? 'Close navigation' : 'Open navigation'} onClick={() => (open ? close() : setOpen(true))}>
            <Icon name="menu" />
          </button>
          <a className="brand" href="#/overview" aria-label="AgentGov overview">
            <img src="icon.svg" alt="" width={26} height={26} />
            <span className="brand-text"><span className="brand-name">AgentGov</span></span>
          </a>
          <span className="topbar-page">{title}</span>
        </header>
        <div className="scrim" hidden={!open} onClick={close} />
        <nav id="nav" className="nav" aria-label="Admin center" data-open={open ? 'true' : 'false'}>
          <a className="brand nav-brand" href="#/overview">
            <img src="icon.svg" alt="" width={30} height={30} />
            <span className="brand-text"><span className="brand-name">AgentGov</span><span className="brand-sub">Admin center</span></span>
          </a>
          {MENU.map(({ group, items }) => {
            // A group of the menu shows only with something in it.
            const empty = items.every(([nav]) => !shows(nav));
            const labelId = group ? `nav-group-${group.toLowerCase()}` : undefined;
            return [
              group ? <p key={`${group}-label`} className="nav-group-label" id={labelId} hidden={empty}>{group}</p> : null,
              <ul key={group || 'top'} className="nav-list" role="list" aria-labelledby={labelId} hidden={empty}>
                {items.map(([nav, href, icon, label]) => (
                  <li key={nav} hidden={!shows(nav)}>
                    <a href={href} data-nav={nav} aria-current={active === nav ? 'page' : undefined}>
                      <Icon name={icon} />
                      <span>{nav === 'findings' && isPerson() ? 'Your issues' : label}</span>
                      {nav === 'approvals' ? badge(badges.approvals.count, badges.approvals.tone, 'pending') : null}
                      {nav === 'findings' ? badge(badges.findings.count, badges.findings.tone, 'open') : null}
                    </a>
                  </li>
                ))}
              </ul>,
            ];
          })}
          <div className="nav-foot">
            <button type="button" className="nav-action" aria-label={`Theme: ${theme}. Select to switch theme.`}
              onClick={() => setTheme(nextTheme())}>
              <Icon name={THEME_ICONS[theme]} /><span>{`Theme: ${theme}`}</span>
            </button>
            <button type="button" className="nav-action" onClick={onSignOut}><Icon name="signout" /><span>Sign out</span></button>
            <p className="nav-meta">{meta}</p>
          </div>
        </nav>
        <PageHost onPage={onPage} focusFirst={focusFirst} />
      </div>
    </>
  );
}
