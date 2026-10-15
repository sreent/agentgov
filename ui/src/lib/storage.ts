// The browser's storage, which a privacy setting can block: the app still works for this
// page view without it.

type Area = 'localStorage' | 'sessionStorage';

export function readStore(area: Area, key: string): string | null {
  try {
    return window[area].getItem(key);
  } catch {
    return null;
  }
}

export function writeStore(area: Area, key: string, value: string | null): void {
  try {
    if (value == null) window[area].removeItem(key);
    else window[area].setItem(key, value);
  } catch {
    /* storage blocked */
  }
}
