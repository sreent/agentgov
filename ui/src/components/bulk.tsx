// What an action on many at once did.

import { cap, fmt, plural } from '../lib/format';
import type { ManyResult } from '../lib/shared';
import { ask } from './dialog';
import { toast } from './toast';

/** A word when all were done; otherwise those left as they were, and why. */
export async function manyDone(result: ManyResult, verb: string, noun: string): Promise<void> {
  const done = result.done?.length || 0;
  const left = result.left || [];
  if (!left.length) {
    toast(`${verb} ${plural(done, noun)}.`);
    return;
  }
  // Those left for the same reason, together: often all of them.
  const byWhy = new Map<string, string[]>();
  for (const x of left) {
    const why = cap(x.why);
    if (!byWhy.has(why)) byWhy.set(why, []);
    byWhy.get(why)!.push(x.title || x[noun]);
  }
  await ask({
    title: done ? `${verb} ${fmt(done)} of ${plural(done + left.length, noun)}` : `No ${noun} was ${verb.toLowerCase()}`,
    text: `${left.length === 1 ? 'This one was' : `These ${fmt(left.length)} were`} left as ${left.length === 1 ? 'it was' : 'they were'}:`,
    iconName: done ? 'info' : 'alert-circle', confirm: 'OK', cancel: null, wide: true,
    extra: (
      <ul className="apply-results" role="list">
        {[...byWhy].map(([why, names]) => (
          <li key={why} className="left-group">
            <strong>{names.length > 1 ? `${why} (${fmt(names.length)})` : why}</strong>
            <span className="muted break">{names.join(', ')}</span>
          </li>
        ))}
      </ul>
    ),
  });
}
