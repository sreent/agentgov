// The admin center's icons: stroked paths on a 24-pixel grid, drawn in the text's colour.

const ICONS: Record<string, string> = {
  overview: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  agents: 'M7 9h10a3 3 0 0 1 3 3v5a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3v-5a3 3 0 0 1 3-3zM12 9V5M9.5 14.5v.01M14.5 14.5v.01',
  map: 'M4 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0M16 6a2 2 0 1 0 4 0a2 2 0 1 0-4 0M16 18a2 2 0 1 0 4 0a2 2 0 1 0-4 0M7.8 11.1l8.4-4.2M7.8 12.9l8.4 4.2',
  approvals: 'M9 4h6v3H9zM8 5.5H6V20h12V5.5h-2M9 13.5l2 2 4-4',
  toolservers: 'M4 4h16v7H4zM4 13h16v7H4zM8 7.5v.01M8 16.5v.01',
  findings: 'M12 3.5l9 16H3zM12 10v4M12 17v.01',
  policies: 'M12 3l7.5 3v6c0 4.4-3.2 7.9-7.5 9-4.3-1.1-7.5-4.6-7.5-9V6zM9 12l2 2 4-4',
  ledger: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.7l1-1',
  check: 'M5 12.5l4.5 4.5L19 7',
  'check-circle': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M8 12.5l2.7 2.7L16 9.5',
  'check-double': 'M2 12.5l4.5 4.5L16 7M12 15.5l1.5 1.5L22 8',
  x: 'M6 6l12 12M18 6L6 18',
  ban: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M5.7 5.7l12.6 12.6',
  clock: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7v5l3 2',
  'user-check': 'M5 8a4 4 0 1 0 8 0a4 4 0 1 0-8 0M3 21c0-3.3 2.7-6 6-6s6 2.7 6 6M16 11l2 2 4-4',
  user: 'M8 7a4 4 0 1 0 8 0a4 4 0 1 0-8 0M4 21c0-4 3.6-7 8-7s8 3 8 7',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM9 12a3 3 0 1 0 6 0a3 3 0 1 0-6 0',
  trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3',
  power: 'M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0',
  refresh: 'M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5',
  undo: 'M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  menu: 'M4 7h16M4 12h16M4 17h16',
  sun: 'M8 12a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z',
  monitor: 'M3 5h18v11H3zM8 20h8M12 16v4',
  signout: 'M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11',
  chevron: 'M9 6l6 6-6 6',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  lock: 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3',
  octagon: 'M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2zM12 8v5M12 16v.01',
  triangle: 'M12 3.5l9 16H3zM12 10v4M12 17v.01',
  'alert-circle': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7.5v5.5M12 16.5v.01',
  info: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 11v5M12 8v.01',
  minus: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M8 12h8',
  key: 'M3 15a4 4 0 1 0 8 0a4 4 0 1 0-8 0M10 12l9-9M15 7l3 3M17 5l2 2',
  play: 'M7 4l13 8-13 8z',
  shield: 'M12 3l7.5 3v6c0 4.4-3.2 7.9-7.5 9-4.3-1.1-7.5-4.6-7.5-9V6z',
  'shield-check': 'M12 3l7.5 3v6c0 4.4-3.2 7.9-7.5 9-4.3-1.1-7.5-4.6-7.5-9V6zM9 12l2 2 4-4',
  external: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
  plus: 'M12 5v14M5 12h14',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4',
  upload: 'M12 15V4M7 9l5-5 5 5M5 20h14',
  access: 'M5 8a4 4 0 1 0 8 0a4 4 0 1 0-8 0M3 21c0-3.3 2.7-6 6-6 1.2 0 2.3.3 3.2.9M17 14a2 2 0 1 0 0 4a2 2 0 1 0 0-4M18.4 15.6L22 12M20.5 13.5l1.5 1.5',
  platforms: 'M7 19h10.5a4.5 4.5 0 0 0 .5-8.98A6 6 0 0 0 6.34 9.03 5 5 0 0 0 7 19z',
  features: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4',
  models: 'M7 7h10v10H7zM10 10h4v4h-4zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
  developers: 'M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14',
  secops: 'M10 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8',
  ticket: 'M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v3a2 2 0 0 0 0 4v3a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-3a2 2 0 0 0 0-4zM10 5v2M10 11v2M10 17v2',
  compliance: 'M7 3h7l5 5v13H7zM14 3v5h5M10 14l2 2 4-4',
  register: 'M6 4h12v17H6zM9 8h6M9 12h6M9 16h4',
  teams: 'M9 7a3 3 0 1 0 6 0a3 3 0 1 0-6 0M3 20c0-3.3 2.7-6 6-6h6c3.3 0 6 2.7 6 6M4 10a2 2 0 1 0 4 0a2 2 0 1 0-4 0M16 10a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
};

interface IconProps {
  name: string;
  /** Said by screen readers; without it the icon is decoration they skip. */
  label?: string;
  cls?: string;
}

export function Icon({ name, label, cls }: IconProps) {
  return (
    <span className={cls ? `ico ${cls}` : 'ico'} {...(label ? { role: 'img', 'aria-label': label } : { 'aria-hidden': true })}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" focusable="false">
        <path d={ICONS[name] || ICONS.info} />
      </svg>
    </span>
  );
}
