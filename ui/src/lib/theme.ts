// Light, dark, or as the system says, kept in this browser.

import { readStore, writeStore } from './storage';

const THEME_KEY = 'agentgov.theme';
export const THEMES = ['system', 'light', 'dark'] as const;
export type Theme = (typeof THEMES)[number];

export function applyTheme(mode: string | null): void {
  const root = document.documentElement;
  if (mode === 'light' || mode === 'dark') root.dataset.theme = mode;
  else delete root.dataset.theme;
}

export function currentTheme(): Theme {
  const mode = document.documentElement.dataset.theme;
  return mode === 'light' || mode === 'dark' ? mode : 'system';
}

export function applySavedTheme(): void {
  applyTheme(readStore('localStorage', THEME_KEY));
}

export function nextTheme(): Theme {
  const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
  applyTheme(next);
  writeStore('localStorage', THEME_KEY, next === 'system' ? null : next);
  return next;
}
