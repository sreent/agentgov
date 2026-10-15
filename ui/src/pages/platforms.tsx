// NOT YET PORTED: the page, and PlatformCard (used on an agent's page), are placeholders.

import { stubPage } from './stub';

export const platformsPage = stubPage(/^\/platforms$/, 'platforms', 'Platforms');

/** What a platform reports about an agent (platformCard(a, v, where)). PLACEHOLDER until ported. */
export function PlatformCard(_props: { a: any; v: any; where: any }) {
  return null;
}
