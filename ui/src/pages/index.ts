// Every page, by its address. The first whose pattern matches is shown: the more specific
// ones (/findings/teams) come before the general (/findings/<id>).

import type { PageDef } from '../lib/router';
import { accessPage } from './access';
import { agentPage } from './agent';
import { agentsPage } from './agents';
import { approvalsPage } from './approvals';
import { compliancePage } from './compliance';
import { developersPage } from './developers';
import { featuresPage } from './features';
import { findingPage } from './finding';
import { findingTypesPage } from './findingTypes';
import { findingsPage } from './findings';
import { ledgerPage } from './ledger';
import { mapPage } from './map';
import { modelsPage } from './models';
import { overviewPage } from './overview';
import { platformsPage } from './platforms';
import { policiesPage } from './policies';
import { registerPage } from './register';
import { secopsPage } from './secops';
import { teamsPage } from './teams';
import { toolserversPage } from './toolservers';

export const PAGES: PageDef[] = [
  overviewPage,
  agentsPage,
  agentPage,
  mapPage,
  approvalsPage,
  toolserversPage,
  findingsPage,
  teamsPage,
  findingTypesPage,
  findingPage,
  policiesPage,
  ledgerPage,
  compliancePage,
  registerPage,
  accessPage,
  platformsPage,
  featuresPage,
  modelsPage,
  developersPage,
  secopsPage,
];
