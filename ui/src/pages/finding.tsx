import { stubPage } from './stub';

export const findingPage = stubPage(/^\/findings\/([^/]+)$/, 'findings', 'Issue');
