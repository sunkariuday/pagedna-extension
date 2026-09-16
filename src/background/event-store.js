import { history } from './baseline-manager.js';
export async function recentEvents(limit = 50) { return history(limit); }
