// The page the address names: loaded, then shown, in the main area. Going to another page
// starts it afresh; refresh() loads the same page again and keeps what was typed and chosen
// on it, the scroll and the focus.

import { Component, useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { Icon } from '../components/Icon';
import { PageHead } from '../components/ui';
import { PAGES } from '../pages';
import { parseHash, refresh, setRefresher, type PageContext, type PageDef } from '../lib/router';
import { home, isPerson, isScoped, personHome, personPages, TEAM_PAGES } from '../lib/session';

interface Shown {
  page: PageDef;
  ctx: PageContext;
  data?: unknown;
  error?: any;
  // Which visit of a page: a new one each time the address changes.
  visit: number;
  soft: boolean;
}

export function ErrorView({ title, error }: { title: string; error: any }) {
  return (
    <div className="page error-view">
      <PageHead title={title} />
      <div className="callout" data-tone="critical" role="alert">
        <Icon name="alert-circle" />
        <div className="callout-body">
          <strong>{`${title} couldn't be loaded.`}</strong>
          <span>{error?.message || String(error)}</span>
          <div className="btn-row" style={{ marginTop: 6 }}>
            <button type="button" className="btn btn--sm" onClick={() => refresh()}><Icon name="refresh" />Try again</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// A page that fails as it is drawn says so, instead of leaving the area blank; loaded
// again (Try again), it is drawn again.
class Boundary extends Component<{ title: string; shown: unknown; children: ReactNode }, { error: any }> {
  state = { error: null };
  static getDerivedStateFromError(error: any) {
    return { error };
  }
  componentDidUpdate(prev: { shown: unknown }) {
    if (prev.shown !== this.props.shown && this.state.error) this.setState({ error: null });
  }
  render() {
    return this.state.error ? <ErrorView title={this.props.title} error={this.state.error} /> : this.props.children;
  }
}

function resolve(path: string): { page: PageDef; match: RegExpMatchArray } | null {
  for (const page of PAGES) {
    const match = path.match(page.re);
    if (match) return { page, match };
  }
  return null;
}

export function PageHost({ onPage, focusFirst }: {
  /** The page's menu entry and title, as soon as they are known. */
  onPage: (nav: string, title: string) => void;
  /** Move the focus to the first page's heading (after signing in). */
  focusFirst: boolean;
}) {
  const [shown, setShown] = useState<Shown | null>(null);
  const [busy, setBusy] = useState(false);
  const seq = useRef(0);
  const visit = useRef(0);
  const waiting = useRef<(() => void)[]>([]);
  const firstView = useRef(true);
  const main = useRef<HTMLElement>(null);

  const settle = () => {
    const done = waiting.current;
    waiting.current = [];
    done.forEach((d) => d());
  };

  const load = useCallback(async (soft: boolean) => {
    const { path, params } = parseHash();
    const found = resolve(path);
    // Somewhere they can't go, or nowhere: their first page.
    if (!found) return void window.location.replace(home());
    const { page, match } = found;
    if (isPerson() && !personPages().includes(page.nav)) return void window.location.replace(personHome());
    if (isScoped() && (!TEAM_PAGES.includes(page.nav) || page.orgWide)) return void window.location.replace(home());
    const mine = ++seq.current;
    onPage(page.nav, page.title);
    setBusy(true);
    const ctx: PageContext = { path, match, params };
    let next: Shown;
    try {
      next = { page, ctx, data: await page.load(ctx), visit: visit.current, soft };
    } catch (error: any) {
      if (mine !== seq.current) return;
      // Signed out: the shell shows the sign-in page.
      if (error?.status === 401) {
        setBusy(false);
        settle();
        return;
      }
      next = { page, ctx, error, visit: visit.current, soft };
    }
    if (mine !== seq.current) return;
    setShown(next);
    setBusy(false);
  }, [onPage]);

  useEffect(() => {
    const go = () => {
      visit.current += 1;
      void load(false);
    };
    go();
    window.addEventListener('hashchange', go);
    setRefresher(() => new Promise<void>((done) => {
      waiting.current.push(done);
      void load(true);
    }));
    return () => {
      window.removeEventListener('hashchange', go);
      setRefresher(null);
      settle();
    };
  }, [load]);

  // Shown: the window's title, and, on a page just gone to, the top of it, with the focus
  // on its heading (except the first page after the app opens, unless just signed in).
  useLayoutEffect(() => {
    if (!shown) return;
    const title = shown.data !== undefined && shown.page.titleOf ? shown.page.titleOf(shown.data as never) : shown.page.title;
    document.title = `${title} · AgentGov`;
    onPage(shown.page.nav, title);
    if (!shown.soft) {
      window.scrollTo(0, 0);
      if (!firstView.current || focusFirst) main.current?.querySelector<HTMLElement>('h1')?.focus({ preventScroll: true });
    }
    firstView.current = false;
    settle();
  }, [shown, onPage, focusFirst]);

  const { page, ctx, data, error, visit: key } = shown || {};
  const View = page?.View;
  return (
    <main id="main" ref={main} tabIndex={-1} className={busy ? 'is-loading' : undefined} aria-busy={busy || undefined}>
      {!shown || !page || !ctx ? (
        <p className="loading-line">Loading…</p>
      ) : error ? (
        <ErrorView title={page.title} error={error} />
      ) : View ? (
        <Boundary key={key} title={page.title} shown={shown}>
          <View key={key} data={data} ctx={ctx} />
        </Boundary>
      ) : null}
    </main>
  );
}
