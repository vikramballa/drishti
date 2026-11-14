// Small inline icon set (24×24, 1.75 stroke, round joins). Drawn here so
// the UI needs no icon library and works offline.
import type { JSX } from 'preact';

const P: Record<string, JSX.Element> = {
  // verdicts
  good: <><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" /><path d="M8.8 12.2l2.2 2.2 4.4-4.6" /></>,
  caution: <><path d="M12 3.5L2.8 19.5h18.4z" /><path d="M12 10v4" /><path d="M12 17.2v.1" /></>,
  danger: <><path d="M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z" /><path d="M12 7.5v5.5" /><path d="M12 16.4v.1" /></>,
  unknown: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.4a2.5 2.5 0 014.8 1c0 1.7-2.4 2-2.4 3.6" /><path d="M12 17.2v.1" /></>,
  // permissions
  camera: <><path d="M3 8h3l2-3h8l2 3h3v11H3z" /><circle cx="12" cy="13" r="3.5" /></>,
  mic: <><rect x="9" y="3" width="6" height="11" rx="3" /><path d="M5.5 11a6.5 6.5 0 0013 0" /><path d="M12 17.5V21" /></>,
  screen: <><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M8 20h8" /><path d="M12 16v4" /><circle cx="12" cy="10" r="2" /></>,
  keyboard: <><rect x="2.5" y="6" width="19" height="12" rx="2" /><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10" /></>,
  location: <><path d="M12 21s-6.5-6-6.5-11a6.5 6.5 0 0113 0c0 5-6.5 11-6.5 11z" /><circle cx="12" cy="10" r="2.4" /></>,
  contacts: <><circle cx="12" cy="8.5" r="3.5" /><path d="M5 20c.8-3.6 3.6-5.5 7-5.5s6.2 1.9 7 5.5" /></>,
  photos: <><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="9.5" r="1.8" /><path d="M21 16l-5-5-8 9" /></>,
  calendar: <><rect x="3.5" y="5" width="17" height="15" rx="2" /><path d="M3.5 10h17M8 3v4M16 3v4" /></>,
  clipboard: <><rect x="6" y="4.5" width="12" height="16" rx="2" /><path d="M9.5 3h5v3h-5z" /></>,
  folder: <path d="M3 6.5A1.5 1.5 0 014.5 5H9l2 2.5h8.5A1.5 1.5 0 0121 9v9.5a1.5 1.5 0 01-1.5 1.5h-15A1.5 1.5 0 013 18.5z" />,
  key: <><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M16.5 6.5l2.5 2.5M14 9l2 2" /></>,
  automation: <><path d="M5 19L15 9" /><path d="M14 4l1 2.2L17.2 7 15 8l-1 2.2L13 8l-2.2-1L13 6z" /><path d="M19 13l.6 1.4 1.4.6-1.4.6L19 17l-.6-1.4-1.4-.6 1.4-.6z" /></>,
  power: <><path d="M12 3v8" /><path d="M7 6.3a8 8 0 1010 0" /></>,
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.6 2.6 3.8 5.6 3.8 9s-1.2 6.4-3.8 9c-2.6-2.6-3.8-5.6-3.8-9S9.4 5.6 12 3z" /></>,
  wifi: <><path d="M2.5 9a14 14 0 0119 0M5.8 12.5a9 9 0 0112.4 0M9 16a4.5 4.5 0 016 0" /><path d="M12 19.5v.1" /></>,
  bluetooth: <path d="M7 7.5l10 9L12 21V3l5 4.5-10 9" />,
  usb: <><path d="M12 21V5M12 3l-2.5 3h5z" /><path d="M12 15l-4-2.5V10M12 13l4-2.5V8" /><circle cx="12" cy="20" r="1.2" /></>,
  terminal: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M12.5 15H17" /></>,
  shield: <path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" />,
  eye: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" /><circle cx="12" cy="12" r="3" /></>,
  heart: <path d="M12 20s-8-4.6-8-10.3A4.4 4.4 0 0112 7a4.4 4.4 0 018 2.7C20 15.4 12 20 12 20z" />,
  home: <><path d="M4 11l8-7 8 7" /><path d="M6 9.5V20h12V9.5" /></>,
  // navigation
  summary: <><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>,
  ask: <><path d="M4 5h16v11H9l-5 4z" /><path d="M8.5 9.5h7M8.5 12.5h4.5" /></>,
  checks: <><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" /><path d="M9 12l2 2 4-4" /></>,
  details: <><circle cx="11" cy="11" r="6.5" /><path d="M20 20l-4.3-4.3" /></>,
  inside: <><path d="M3.5 7.5L12 3l8.5 4.5v9L12 21l-8.5-4.5z" /><path d="M3.5 7.5L12 12l8.5-4.5M12 12v9" /></>,
  code: <><path d="M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5M13.5 4.5l-3 15" /></>,
  graph: <><rect x="9" y="3" width="6" height="4.5" rx="1" /><rect x="3" y="16.5" width="6" height="4.5" rx="1" /><rect x="15" y="16.5" width="6" height="4.5" rx="1" /><path d="M12 7.5v4.5M6 16.5V12h12v4.5" /></>,
  calls: <><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" /><path d="M7.5 8l3.3 7.6M16.5 8l-3.3 7.6M8.5 6h7" /></>,
  functions: <><path d="M4 6h16M4 12h16M4 18h10" /></>,
  hex: <><path d="M5 4h14v16H5z" /><path d="M8.5 8.5h2M13.5 8.5h2M8.5 12h2M13.5 12h2M8.5 15.5h2" /></>,
  strings: <><path d="M5 7V5h14v2M12 5v14M9 19h6" /></>,
  imports: <><path d="M12 3v12M7.5 10.5L12 15l4.5-4.5" /><path d="M4 17v3h16v-3" /></>,
  exports: <><path d="M12 15V3M7.5 7.5L12 3l4.5 4.5" /><path d="M4 17v3h16v-3" /></>,
  search: <><circle cx="11" cy="11" r="6.5" /><path d="M20 20l-4.3-4.3M8.5 11h5" /></>,
  diff: <><path d="M6 3v12M6 15a3 3 0 103 3M18 21V9M18 9a3 3 0 10-3-3" /><path d="M9 6h4M11 18h4" /></>,
  notes: <><path d="M5 3h10l4 4v14H5z" /><path d="M15 3v4h4M8.5 12h7M8.5 16h5" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z" /></>,
  mac: <><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M2 19.5h20" /></>,
  upload: <><path d="M12 16V4M7.5 8.5L12 4l4.5 4.5" /><path d="M4 15v4.5h16V15" /></>,
  app: <><rect x="4" y="4" width="16" height="16" rx="4" /><path d="M9 9h6v6H9z" /></>,
  file: <><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4" /></>,
  chevron: <path d="M9 6l6 6-6 6" />,
  down: <path d="M6 9l6 6 6-6" />,
  external: <><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 14v5H5V6h5" /></>,
  copy: <><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V5a1 1 0 00-1-1H5a1 1 0 00-1 1v10a1 1 0 001 1h3" /></>,
  play: <path d="M7 4.5v15l12-7.5z" />,
  refresh: <><path d="M20 11a8 8 0 00-14.5-4.5L4 8M4 4v4h4M4 13a8 8 0 0014.5 4.5L20 16M20 20v-4h-4" /></>,
  close: <path d="M6 6l12 12M18 6L6 18" />,
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  dot: <circle cx="12" cy="12" r="3.5" />,
  sparkle: <path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z" />,
  lock: <><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5V8a4 4 0 018 0v2.5" /></>,
  cloud: <path d="M7 18.5h10.5a4 4 0 00.6-8 6 6 0 00-11.5 1.6A3.3 3.3 0 007 18.5z" />,
  help: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.4a2.5 2.5 0 014.8 1c0 1.7-2.4 2-2.4 3.6M12 17.2v.1" /></>,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  power2: <path d="M13 3L5 14h6l-1 7 8-11h-6z" />,
  wrench: <path d="M14.5 6.5a4 4 0 015.2 5.2L12 19.5a2.1 2.1 0 01-3-3l7.8-7.8a4 4 0 01-2.3-2.2zM4 20l3-3" />,
  tracker: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r=".9" /></>,
};

export function Icon({ name, size = 18, class: cls }: { name: string; size?: number; class?: string }) {
  return (
    <svg class={`ico${cls ? ` ${cls}` : ''}`} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      {P[name] ?? P.dot}
    </svg>
  );
}
