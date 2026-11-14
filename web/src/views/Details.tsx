// Hidden details: every metadata field ExifTool found, Office macros
// (oletools) with their code, and files embedded inside (binwalk).
import { useState } from 'preact/hooks';
import { api, FileTool } from '../api';
import { Icon } from '../components/Icon';
import { useAsync } from '../components/hooks';
import { notify, route, toolVersion } from '../store';
import { ResultBody } from './Checks';

function RunOrInstall({ t, sha }: { t: FileTool | undefined; sha: string }) {
  if (!t) return null;
  if (!t.installed) return <p class="small muted">{t.name} is not installed. In Terminal: <code>{t.install}</code></p>;
  if (t.status === 'running' || t.status === 'queued') return <p class="small muted"><span class="spin" /> {t.name} is reading the file…</p>;
  if (t.status === 'failed') return <p class="small bad">{t.error}</p>;
  return <button class="primary" onClick={() => api.runTool(sha, t.id).then(() => { toolVersion.value++; }, (e: Error) => notify(e.message, 'error'))}>Run {t.name}</button>;
}

export function Details() {
  const sha = route.value.sha!;
  const tools = useAsync(() => api.fileTools(sha), [sha, toolVersion.value]);
  const [q, setQ] = useState('');
  const byId = (id: string) => tools.data?.tools.find((t) => t.id === id);
  const ex = byId('exiftool');
  const ole = byId('oletools');
  const bw = byId('binwalk');
  const fields = (ex?.result?.data?.fields as { group: string; tag: string; value: string }[] | undefined) ?? [];
  const hl = (ex?.result?.data?.highlights as { label: string; value: string }[] | undefined) ?? [];
  const gps = ex?.result?.data?.gps as { lat: number; lon: number } | null | undefined;
  const macros = (ole?.result?.data?.macros as { name: string; stream: string; code: string }[] | undefined) ?? [];
  const ql = q.toLowerCase();
  const shown = fields.filter((f) => !ql || f.tag.toLowerCase().includes(ql) || f.value.toLowerCase().includes(ql) || f.group.toLowerCase().includes(ql));
  return (
    <div class="page">
      <header class="page-head"><div><h1>Hidden details</h1><p class="muted">Information stored inside the file that you normally don't see: who made it, with what, when, and sometimes where.</p></div></header>
      <section class="card">
        <h3><Icon name="details" size={16} /> Metadata <span class="muted small">from ExifTool</span></h3>
        {!ex?.result && <RunOrInstall t={ex} sha={sha} />}
        {gps && (
          <p class="callout warn"><Icon name="location" size={16} /> Recorded location: {gps.lat.toFixed(5)}, {gps.lon.toFixed(5)} ·{' '}
            <a href={`https://www.openstreetmap.org/?mlat=${gps.lat}&mlon=${gps.lon}#map=15/${gps.lat}/${gps.lon}`} target="_blank" rel="noopener noreferrer">open map</a>
          </p>
        )}
        {hl.length > 0 && <dl class="facts big">{hl.map((h) => <><dt>{h.label}</dt><dd>{h.value}</dd></>)}</dl>}
        {fields.length > 0 && (
          <details>
            <summary>All {fields.length} fields</summary>
            <input type="search" class="wide-input" placeholder="Filter fields…" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label="Filter fields" />
            <div class="meta-table">{shown.map((f) => <div class="meta"><span class="mk">{f.tag}</span><span class="mv">{f.value}</span><span class="src">{f.group}</span></div>)}</div>
          </details>
        )}
      </section>
      {ole && (
        <section class="card">
          <h3><Icon name="file" size={16} /> Macros <span class="muted small">from oletools</span></h3>
          {ole.result ? <ResultBody r={ole.result as never} max={15} /> : <RunOrInstall t={ole} sha={sha} />}
          {macros.map((m) => (
            <details><summary class="mono">{m.name} <span class="muted small">{m.stream}</span></summary><pre class="codeblock">{m.code}</pre></details>
          ))}
        </section>
      )}
      {bw && (
        <section class="card">
          <h3><Icon name="inside" size={16} /> Files hidden inside <span class="muted small">from binwalk</span></h3>
          {bw.result ? <ResultBody r={bw.result as never} max={60} /> : <RunOrInstall t={bw} sha={sha} />}
        </section>
      )}
    </div>
  );
}
