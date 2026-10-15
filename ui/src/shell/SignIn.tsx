// Signing in: with single sign-on when the control plane has it, or with an API token, which
// is kept in this browser tab only.

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, API_ROOT, ApiError, getInfo } from '../lib/api';
import { mayOpen, roleName, setToken, type Me } from '../lib/session';

export function SignIn({ message, onSignedIn }: { message?: string; onSignedIn: (who: Me) => void }) {
  const [error, setError] = useState(message || '');
  const [show, setShow] = useState(false);
  const [working, setWorking] = useState(false);
  const [sso, setSso] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.title = 'Sign in · AgentGov';
    input.current?.focus();
    let live = true;
    void getInfo().then((info) => {
      if (!live || !info?.sso?.enabled) return;
      // Back to the page the link was for (an issue, from an email) once signed in.
      const login = new URL('auth/login', API_ROOT);
      const { hash } = window.location;
      if (/^#\/[\w\-/?=&.%]*$/.test(hash) && hash.length <= 500) login.searchParams.set('next', hash);
      setSso(login.href);
    });
    return () => {
      live = false;
    };
  }, []);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const value = input.current!.value.trim();
    if (!value) {
      setError('Enter an API token.');
      input.current!.focus();
      return;
    }
    setWorking(true);
    try {
      setToken(value);
      const who = await api<Me>('v1/me', { signingIn: true });
      if (!mayOpen(who)) throw new ApiError(403, '', `its role is ${roleName(who.role)}`);
      onSignedIn(who);
    } catch (ex: any) {
      setToken(null);
      if (ex.status === 401) setError('That token was not accepted. Check it for missing or extra characters, or ask an administrator for a new API key.');
      else if (ex.status === 403) setError(`This token can't open the admin center (${ex.detail || 'its role is not allowed'}). Use an admin, approver, secops or auditor key.`);
      else setError(ex.message);
      setWorking(false);
      input.current!.focus();
      input.current!.select();
    }
  };

  return (
    <div id="signin" className="signin">
      <form className="signin-card" noValidate onSubmit={onSubmit}>
        <div className="brand brand--lg">
          <img src="icon.svg" alt="" width={36} height={36} />
          <span className="brand-text"><span className="brand-name">AgentGov</span><span className="brand-sub">Admin center</span></span>
        </div>
        <h1 className="signin-title">Sign in</h1>
        {sso ? (
          <div className="sso">
            <a className="btn btn--primary btn--block" href={sso}>Sign in with single sign-on</a>
            <p className="signin-lede">With your work account. Owners and others sent an issue or an approval request sign in here too.</p>
            <p className="signin-or"><span>or use an API token</span></p>
          </div>
        ) : null}
        <p className="signin-lede">Paste an API token for this control plane. Admins, approvers, the security team and auditors can sign in; what you can change depends on the token&apos;s role.</p>
        <div className="field">
          <label htmlFor="token">API token</label>
          <div className="input-group">
            <input ref={input} id="token" name="token" type={show ? 'text' : 'password'} autoComplete="off" spellCheck={false}
              autoCapitalize="off" required aria-describedby="token-hint signin-error" />
            <button type="button" className="btn btn--ghost" aria-pressed={show} aria-controls="token" onClick={() => setShow(!show)}>
              {show ? 'Hide' : 'Show'}
            </button>
          </div>
          <p id="token-hint" className="hint">Kept in this browser tab only, and cleared when you close the tab or sign out.</p>
        </div>
        <p id="signin-error" className="form-error" role="alert" hidden={!error}>{error}</p>
        <button type="submit" className={sso ? 'btn btn--block' : 'btn btn--primary btn--block'} disabled={working}>
          {working ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
