// App state: hash router (gives free back/forward history), current binary,
// live jobs, theme. Signals keep re-renders surgical.
import { signal, computed } from '@preact/signals';
import { api, BinaryDetail, connectEvents, invalidate, Job, ServerEvent } from './api';

export type View = 'overview' | 'ask' | 'checks' | 'weakspots' | 'details' | 'inside' | 'functions' | 'code' | 'graph' | 'hex' | 'strings' | 'imports' | 'exports' | 'callgraph' | 'notes' | 'settings' | 'search' | 'diff' | 'mac';
export interface Route { sha: string | null; view: View; addr: string | null }

function parse(): Route {
  const h = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = h.split('?');
  const parts = path.split('/').filter(Boolean);
  const params = new URLSearchParams(query);
  if (parts[0] === 'b' && parts[1]) return { sha: parts[1], view: (parts[2] as View) || 'overview', addr: params.get('a') };
  if (parts[0] === 'settings') return { sha: null, view: 'settings', addr: parts[1] ?? null };
  if (parts[0] === 'mac') return { sha: null, view: 'mac', addr: parts[1] ?? null };
  return { sha: null, view: 'overview', addr: null };
}

export const route = signal<Route>(parse());
window.addEventListener('hashchange', () => { route.value = parse(); });

export function go(r: Partial<Route>) {
  const n = { ...route.value, ...r };
  if (!n.sha) { location.hash = n.view === 'settings' || n.view === 'mac' ? `#/${n.view}${n.addr ? `/${n.addr}` : ''}` : '#/'; return; }
  location.hash = `#/b/${n.sha}/${n.view}${n.addr ? `?a=${n.addr}` : ''}`;
}

/** Navigate to an address: functions open in code view. */
export function goAddr(addr: string, view?: View) {
  const v = view ?? (route.value.view === 'graph' || route.value.view === 'hex' ? route.value.view : 'code');
  go({ addr, view: v });
}

export const binary = signal<BinaryDetail | null>(null);
export const binaryError = signal<string | null>(null);
export const jobs = signal<Record<string, Job & { sha256: string }>>({});
export const toast = signal<{ text: string; kind: 'info' | 'error' | 'ok'; action?: { label: string; run: () => void } } | null>(null);
/** Bumped when data for the current binary changes (analysis done, renames). */
export const dataVersion = signal(0);
/** Bumped on any tool/setup progress event. */
export const toolVersion = signal(0);

/** Simple: plain-language pages only. Expert: all the code views too. */
type Mode = 'simple' | 'expert';
function readMode(): Mode {
  try { return (localStorage.getItem('drishti-mode') as Mode) || 'simple'; } catch { return 'simple'; }
}
export const mode = signal<Mode>(readMode());
export function setMode(m: Mode) {
  mode.value = m;
  try { localStorage.setItem('drishti-mode', m); } catch { /* private mode */ }
}

let toastTimer: number | undefined;
export function notify(text: string, kind: 'info' | 'error' | 'ok' = 'info', action?: { label: string; run: () => void }, ms = 4000) {
  toast.value = { text, kind, action };
  clearTimeout(toastTimer);
  if (ms) toastTimer = window.setTimeout(() => (toast.value = null), ms);
}

export const currentJob = computed(() => {
  const sha = route.value.sha;
  return Object.values(jobs.value).find((j) => j.sha256 === sha && (j.status === 'queued' || j.status === 'running')) ?? null;
});

export async function loadBinary(sha: string) {
  try {
    binaryError.value = null;
    const b = await api.binary(sha);
    if (route.value.sha === sha) binary.value = b;
    if (b.job && (b.job.status === 'queued' || b.job.status === 'running')) jobs.value = { ...jobs.value, [b.job.id]: b.job };
  } catch (e) {
    binaryError.value = (e as Error).message;
  }
}

export function refreshData(sha: string) {
  invalidate(sha);
  dataVersion.value++;
  void loadBinary(sha);
}

// Live events from the server.
connectEvents((e: ServerEvent) => {
  if (e.type === 'job' && e.job_id && e.sha256) {
    const prev = jobs.value[e.job_id];
    const j: Job = { id: e.job_id, sha256: e.sha256, status: e.status ?? prev?.status ?? 'running', phase: e.phase ?? prev?.phase ?? undefined, functions: e.functions ?? prev?.functions ?? 0, instructions: e.instructions ?? prev?.instructions ?? 0, error: e.message ?? undefined };
    jobs.value = { ...jobs.value, [e.job_id]: j };
    if (e.status === 'done' && e.sha256 === route.value.sha) {
      refreshData(e.sha256);
      notify(`Analysis complete — ${j.functions.toLocaleString()} functions`, 'ok');
    }
    if (e.status === 'failed' && e.sha256 === route.value.sha) notify(`Analysis failed: ${e.message ?? ''}`, 'error', undefined, 8000);
  } else if (e.type === 'tool') {
    // A tool finished or changed state: refresh what depends on it.
    toolVersion.value++;
    if (e.sha256 === route.value.sha && (e.status === 'done' || e.status === 'failed')) {
      invalidate(e.sha256 ?? undefined);
      dataVersion.value++;
      const name = e.phase ?? 'tool';
      if (e.status === 'failed' && !name.startsWith('decomp')) notify(`${name}: ${e.message ?? 'failed'}`, 'error', undefined, 8000);
    }
  } else if (e.type === 'annotation' && e.sha256 === route.value.sha) {
    invalidate(e.sha256 ?? undefined);
    dataVersion.value++;
  } else if (e.type === 'binary_changed' && e.sha256) {
    const [old, path] = (e.message ?? '').split('|');
    if (old === route.value.sha) {
      const ns = e.sha256;
      notify(`${path?.split('/').pop() ?? 'File'} changed on disk — re-analysed`, 'info', { label: 'See what changed', run: () => { location.hash = `#/b/${ns}/diff?a=${old}`; } }, 0);
    }
  }
});

// Theme
type Theme = 'light' | 'dark' | 'system';
function readTheme(): Theme {
  try { return (localStorage.getItem('drishti-theme') as Theme) || 'system'; } catch { return 'system'; }
}
export const theme = signal<Theme>(readTheme());
export function applyTheme() {
  const t = theme.value;
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('drishti-theme', t); } catch { /* private mode */ }
}
applyTheme();

export const isMobile = signal(window.matchMedia('(max-width: 760px)').matches);
window.matchMedia('(max-width: 760px)').addEventListener('change', (m) => (isMobile.value = m.matches));

/** A question to ask as soon as the Ask page opens (from suggestion chips). */
export const pendingAsk = signal<string | null>(null);
/** A search to run when the Search view opens (e.g. from "every file"). */
export const pendingSearch = signal<import('./api').SearchOpts | null>(null);
export function askAbout(question: string) {
  pendingAsk.value = question;
  go({ view: 'ask', addr: null });
}
