// A page not yet moved to React: its heading only.

import { PageHead } from '../components/ui';
import type { PageDef } from '../lib/router';

export function stubPage(re: RegExp, nav: string, title: string, more: Partial<PageDef> = {}): PageDef {
  return {
    re, nav, title, ...more,
    load: async () => null,
    View: () => <div className="page"><PageHead title={title} sub="Not yet moved to React." /></div>,
  };
}
