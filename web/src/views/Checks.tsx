// Safety checks: every tool that understands this file (run on demand, in
// a sandbox) plus the opt-in online lookups. Each result leads with one
// plain sentence; the individual matches are listed underneath.
import { useEffect, useState } from 'preact/hooks';
import { api, FileTool, LookupService, ToolResult } from '../api';
import { Icon } from '../components/Icon';
import { Term } from '../components/Term';
import { useAsync } from '../components/hooks';
import { notify, route, toolVersion } from '../store';

const KIND_TITLE: Record<string, string> = {
  safety: 'Safety scans',
  details: 'Hidden details',
  apps: 'Open it up',
};

const VERDICT_LABEL: Record<string, string> = { clean: 'Clean', warning: 'Worth a look', danger: 'Dangerous', info: 'Info', unknown: 'Unknown', error: 'Error' };

export function ResultBody({ r, max = 40, head = true }: { r: ToolResult & Record<string, unknown>; max?: number; head?: boolean }) {
  const [all, setAll] = useState(false);
  const items = r.items ?? [];
  const shown = all ? items : items.slice(0, max);
  return (
    <div class="result">
      {head && <p class="result-head">{r.headline}</p>}
      {shown.length > 0 && (
        <ul class="items">
          {shown.map((i) => (
            <li class={`sev-${i.severity}`}>
              <span class="sevdot" />
              <div><b>{String(i.title)}</b>{i.detail && <div class="muted small">{String(i.detail)}</div>}
                {typeof i.reference === 'string' && i.reference.startsWith('http') && <a class="small" href={i.reference} target="_blank" rel="noopener noreferrer">Learn more</a>}
              </div>
            </li>
          ))}
        </ul>
      )}
      {items.length > max && !all && <button class="link" onClick={() => setAll(true)}>Show all {items.length}</button>}
      {Array.isArray(r.detections) && r.detections.length > 0 && (
        <details><summary>Which antivirus programs flag it ({r.detections.length})</summary>
          <ul class="items">{(r.detections as { engine: string; result: string }[]).map((d) => <li class="sev-high"><span class="sevdot" /><div><b>{d.engine}</b> <span class="muted small">{d.result}</span></div></li>)}</ul>
        </details>
      )}
      {Array.isArray(r.hosts) && (r.hosts as { host: string; known_bad: boolean; link?: string }[]).length > 0 && (
        <ul class="items">{(r.hosts as { host: string; known_bad: boolean; link?: string | null; threats?: string[] }[]).map((h) => (
          <li class={h.known_bad ? 'sev-high' : 'sev-info'}><span class="sevdot" /><div><b class="mono">{h.host}</b> <span class="small muted">{h.known_bad ? `known for malware ${h.threats?.join(', ') ?? ''}` : 'not listed'}</span></div></li>
        ))}</ul>
      )}
      {Array.isArray(r.ips) && (r.ips as unknown[]).length > 0 && (
        <ul class="items">{(r.ips as { ip: string; score: number; country?: string; isp?: string }[]).map((h) => (
          <li class={h.score > 50 ? 'sev-high' : h.score > 10 ? 'sev-medium' : 'sev-info'}><span class="sevdot" /><div><b class="mono">{h.ip}</b> <span class="small muted">abuse score {h.score}% · {h.country ?? ''} {h.isp ?? ''}</span></div></li>
        ))}</ul>
      )}
      <p class="small muted result-foot">
        {typeof r.link === 'string' && <><a href={r.link} target="_blank" rel="noopener noreferrer">Open full report <Icon name="external" size={12} /></a> · </>}
        {r.duration_ms != null && `took ${(r.duration_ms / 1000).toFixed(1)} s`}
        {r.version ? ` · version ${r.version}` : ''}
        {typeof r.checked_at === 'string' ? ` · checked ${new Date(r.checked_at).toLocaleString()}` : r.finished_at ? ` · ${new Date(r.finished_at).toLocaleString()}` : ''}
      </p>
    </div>
  );
}

function ToolCard({ t, sha }: { t: FileTool; sha: string }) {
  const [open, setOpen] = useState(t.result ? t.result.verdict === 'danger' || t.result.verdict === 'warning' : false);
  const busy = t.status === 'running' || t.status === 'queued';
  const run = async () => {
    try { await api.runTool(sha, t.id); toolVersion.value++; } catch (e) { notify((e as Error).message, 'error'); }
  };
  const copy = (s: string) => navigator.clipboard?.writeText(s).then(() => notify('Install command copied. Paste it into Terminal.', 'ok', undefined, 2500), () => {});
  const v = t.result?.verdict ?? (t.status === 'failed' ? 'error' : null);
  const needsSetup = t.setup && !t.setup.ready;
  return (
    <article class={`tool${v ? ` v-${v}` : ''}`}>
      <header class="tool-head" onClick={() => t.result && setOpen(!open)}>
        <span class="tool-ic"><Icon name={t.kind === 'safety' ? 'checks' : t.kind === 'details' ? 'details' : 'inside'} size={18} /></span>
        <div class="tool-t">
          <b>{t.name}</b>
          <span class="muted small">{t.result ? t.result.headline : t.what}</span>
        </div>
        <div class="tool-side">
          {v && <span class={`pill v-${v}`}>{VERDICT_LABEL[v] ?? v}</span>}
          {busy && <span class="pill running"><span class="spin" /> {t.status === 'queued' ? 'Waiting' : 'Running'}</span>}
          {!t.installed ? (
            <button onClick={(e) => { e.stopPropagation(); copy(t.install); }} title={t.install}>Copy install command</button>
          ) : needsSetup ? (
            <a class="btn" href="#/settings/tools" onClick={(e) => e.stopPropagation()}>Set up</a>
          ) : !busy ? (
            <button class={t.result ? '' : 'primary'} onClick={(e) => { e.stopPropagation(); void run(); }}>{t.result ? 'Run again' : 'Run'}</button>
          ) : null}
        </div>
      </header>
      {t.status === 'failed' && t.error && <p class="small bad tool-err">{t.error}</p>}
      {!t.installed && <p class="small muted tool-err">Not installed. In Terminal: <code>{t.install}</code></p>}
      {needsSetup && t.installed && <p class="small muted tool-err">{t.setup!.note}</p>}
      {t.heavy && !t.result && t.installed && !busy && <p class="small muted tool-err">Can take a few minutes on large programs.</p>}
      {open && t.result && <ResultBody r={t.result as ToolResult & Record<string, unknown>} head={false} />}
      {t.result && !open && <button class="link small" onClick={() => setOpen(true)}>Show results</button>}
    </article>
  );
}

function Lookups({ sha }: { sha: string }) {
  const l = useAsync(() => api.lookups(sha), [sha, toolVersion.value]);
  const [busy, setBusy] = useState<string | null>(null);
  const [res, setRes] = useState<Record<string, LookupService['result']>>({});
  if (!l.data) return null;
  const run = async (s: LookupService) => {
    setBusy(s.id);
    try {
      const r = await api.runLookup(sha, s.id);
      setRes({ ...res, [s.id]: r as LookupService['result'] });
      toolVersion.value++;
    } catch (e) { notify((e as Error).message, 'error', undefined, 7000); } finally { setBusy(null); }
  };
  return (
    <section class="checks-sec">
      <h2><Icon name="cloud" size={18} /> Online checks <span class="muted small">optional, uses the internet</span></h2>
      {!l.data.enabled ? (
        <div class="callout">
          <p><b>Off.</b> Online checks ask public security databases about this file. Only a <Term k="sha256">fingerprint</Term> of the file, or the web and IP addresses found in it, is sent. The file itself is never uploaded.</p>
          <a class="btn primary" href="#/settings/online">Turn on in Settings</a>
        </div>
      ) : (
        l.data.services.map((s) => {
          const r = res[s.id] ?? s.result;
          return (
            <article class={`tool${r ? ` v-${r.verdict}` : ''}`}>
              <header class="tool-head">
                <span class="tool-ic"><Icon name="cloud" size={18} /></span>
                <div class="tool-t"><b>{s.name}</b><span class="muted small">{s.what} Sends {s.sends}.</span></div>
                <div class="tool-side">
                  {r && <span class={`pill v-${r.verdict}`}>{VERDICT_LABEL[r.verdict] ?? r.verdict}</span>}
                  {!s.key_set ? <a class="btn" href="#/settings/online">Add free key</a> :
                    <button class={r ? '' : 'primary'} disabled={busy === s.id} onClick={() => void run(s)}>{busy === s.id ? 'Checking…' : r ? 'Check again' : 'Check'}</button>}
                </div>
              </header>
              {r && <ResultBody r={r} head={false} />}
            </article>
          );
        })
      )}
    </section>
  );
}

export function Checks() {
  const sha = route.value.sha!;
  const tools = useAsync(() => api.fileTools(sha), [sha, toolVersion.value]);
  // Poll while anything runs (events also refresh, this is a fallback).
  useEffect(() => {
    if (!tools.data?.tools.some((t) => t.status === 'running' || t.status === 'queued')) return;
    const id = setTimeout(() => { toolVersion.value++; }, 3000);
    return () => clearTimeout(id);
  }, [tools.data]);
  const list = tools.data?.tools ?? [];
  const runnable = list.filter((t) => t.kind === 'safety' && t.installed && !(t.setup && !t.setup.ready) && t.status !== 'running' && t.status !== 'queued' && !t.result);
  const runAll = async () => {
    for (const t of runnable) {
      try { await api.runTool(sha, t.id); } catch (e) { notify(`${t.name}: ${(e as Error).message}`, 'error'); }
    }
    toolVersion.value++;
  };
  const groups = ['safety', 'details', 'apps'].map((k) => [k, list.filter((t) => t.kind === k)] as const).filter(([, v]) => v.length > 0);
  return (
    <div class="page checks">
      <header class="page-head">
        <div>
          <h1>Safety checks</h1>
          <p class="muted">Each tool reads the file in a locked sandbox with no internet. Nothing is ever run.</p>
        </div>
        {runnable.length > 0 && <button class="primary" onClick={() => void runAll()}><Icon name="play" size={15} /> Run all scans ({runnable.length})</button>}
      </header>
      {tools.loading && !tools.data && <div class="skeleton" style={{ height: '120px' }} />}
      {tools.error && <div class="banner error">{tools.error}</div>}
      {groups.map(([k, ts]) => (
        <section class="checks-sec">
          <h2>{KIND_TITLE[k]}</h2>
          {ts.map((t) => <ToolCard t={t} sha={sha} key={t.id} />)}
        </section>
      ))}
      {list.length === 0 && tools.data && <p class="empty">No installed tool understands this kind of file yet. See <a href="#/settings/tools">Settings → Tools</a>.</p>}
      <Lookups sha={sha} />
    </div>
  );
}
