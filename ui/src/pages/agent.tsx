import { stubPage } from './stub';

export const agentPage = stubPage(/^\/agents\/([^/]+)$/, 'agents', 'Agent');
