// NOT YET PORTED: the page, ModeControl and featureProvenance are placeholders.

import type { ReactNode } from 'react';
import { stubPage } from './stub';

export const featuresPage = stubPage(/^\/features$/, 'features', 'Features');

/** A feature's mode, to choose (modeControl(f)): radios, or its mode where it can't be changed. PLACEHOLDER. */
export function ModeControl(_props: { f: any }) {
  return null;
}

/** Who set a feature's mode (featureProvenance(f)). PLACEHOLDER. */
export function featureProvenance(_f: any): ReactNode {
  return null;
}
